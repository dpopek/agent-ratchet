"""Source trees: every blob under `src/` at one commit, plus the `[project.scripts]` table."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from ..git import Git, show_bytes


@dataclass(frozen=True)
class SourceTree:
    commit: str
    files: Mapping[str, bytes]   # path → blob bytes, for every blob under src/ (symlinks hold their target)
    modes: Mapping[str, str]     # path → git mode, for every entry under src/ (gitlinks included)
    scripts: Mapping[str, str]   # [project.scripts] of pyproject.toml at the commit


class TreeError(ValueError):
    """The commit's tree cannot be read as a source tree."""


def module_name(path: str) -> str | None:
    """`src/a/b.py` → `a.b`; `src/a/__init__.py` → `a`; None for anything that is not an importable module path."""
    if not (path.startswith("src/") and path.endswith(".py")):
        return None
    parts = path[len("src/"):-len(".py")].split("/")
    if parts[-1] == "__init__":
        parts.pop()
    if not parts or not all(part.isidentifier() for part in parts):
        return None
    return ".".join(parts)


def load_tree(git: Git, mirror: Path, commit: str) -> SourceTree:
    listing = git(mirror, "ls-tree", "-r", "-z", "--full-tree", commit, "--", "src/").stdout
    modes: dict[str, str] = {}
    blobs: list[tuple[str, str]] = []
    for entry in listing.split(b"\0"):
        if not entry:
            continue
        meta, _, raw_path = entry.partition(b"\t")
        mode, kind, oid = meta.decode("ascii").split(" ")
        path = raw_path.decode("utf-8", errors="surrogateescape")
        modes[path] = mode
        if kind == "blob":
            blobs.append((path, oid))
    return SourceTree(commit, _cat_blobs(git, mirror, blobs), modes, _scripts(git, mirror, commit))


def _cat_blobs(git: Git, mirror: Path, blobs: list[tuple[str, str]]) -> dict[str, bytes]:
    if not blobs:
        return {}
    out = git(mirror, "cat-file", "--batch", input="".join(f"{oid}\n" for _, oid in blobs).encode("ascii")).stdout
    files: dict[str, bytes] = {}
    pos = 0
    for path, oid in blobs:
        eol = out.find(b"\n", pos)
        header = out[pos:eol].decode("ascii", errors="replace").split(" ") if eol != -1 else []
        if len(header) != 3 or header[0] != oid or header[1] != "blob" or not header[2].isdigit():
            raise TreeError(f"cat-file --batch: unexpected reply {header!r} for {path}")
        start = eol + 1
        end = start + int(header[2])
        if out[end:end + 1] != b"\n":
            raise TreeError(f"cat-file --batch: truncated content for {path}")
        files[path] = out[start:end]
        pos = end + 1
    return files


def _scripts(git: Git, mirror: Path, commit: str) -> dict[str, str]:
    raw = show_bytes(git, mirror, commit, "pyproject.toml")
    if raw is None:
        return {}
    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise TreeError(f"pyproject.toml at {commit} does not parse: {exc}") from exc
    project = data.get("project", {})
    scripts = project.get("scripts", {}) if isinstance(project, dict) else None
    if not isinstance(scripts, dict) or not all(isinstance(v, str) for v in scripts.values()):
        raise TreeError(f"pyproject.toml at {commit}: [project.scripts] is not a table of strings")
    return dict(scripts)
