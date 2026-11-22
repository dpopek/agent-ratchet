"""Test-only builders for real bare repositories (never touches the network)."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Mapping


def _env() -> dict[str, str]:
    return {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}


def _git(cwd: Path, *args: str) -> str:
    r = subprocess.run(("git", *args), cwd=cwd, env=_env(), capture_output=True, stdin=subprocess.DEVNULL,
                       timeout=60, check=False)
    if r.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {r.stderr.decode(errors='replace')}")
    return r.stdout.decode(errors="replace").strip()


def make_bare(root: Path, name: str) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    path = root / f"{name}.git"
    _git(root, "init", "--bare", "-q", "-b", "main", str(path))
    return path


def make_clone(bare: Path, dest: Path) -> Path:
    return make_clone_from_url(str(bare), dest)


def make_clone_from_url(url: str, dest: Path) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    _git(dest.parent, "clone", "-q", url, str(dest))
    return dest


def commit_files(repo: Path, msg: str, files: Mapping[str, bytes | str | None], *,
                 mode: str | None = None) -> str:
    for rel, content in files.items():
        target = repo / rel
        if content is None:
            target.unlink(missing_ok=True)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content.encode() if isinstance(content, str) else content)
        if mode is not None:
            target.chmod(int(mode, 8))
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "--allow-empty", "-m", msg)
    return _git(repo, "rev-parse", "HEAD")


def tag_annotated(repo: Path, tag: str, rev: str = "HEAD") -> str:
    _git(repo, "tag", "-a", tag, "-m", tag, rev)
    return _git(repo, "rev-parse", tag)


def push_all(repo: Path) -> None:
    _git(repo, "push", "-q", "origin", "--all")
    _git(repo, "push", "-q", "origin", "--tags")


def redirect(home: Path, url: str, bare: Path) -> None:
    _git(home, "config", "--file", str(home / ".gitconfig"), "--add", f"url.file://{bare}.insteadOf", url)


def make_upstream(root: Path, tags: Mapping[str, Mapping[str, bytes]], *,
                  lightweight_tags: Mapping[str, str] = {},
                  side_branch_tags: Mapping[str, str] = {}) -> Path:
    bare = make_bare(root, "upstream")
    work = make_clone(bare, root / "upstream-work")
    for tag, files in tags.items():
        commit_files(work, tag, dict(files))
        tag_annotated(work, tag)
    for tag, rev in lightweight_tags.items():
        _git(work, "tag", tag, _git(work, "rev-parse", f"{rev}^{{commit}}"))
    if side_branch_tags:
        _git(work, "checkout", "-q", "-b", "side")
        for tag, message in side_branch_tags.items():
            commit_files(work, message, {})
            tag_annotated(work, tag)
        _git(work, "checkout", "-q", "main")
    push_all(work)
    return bare
