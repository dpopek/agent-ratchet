"""Reach the fleet package from the root suite without installing it.

``fleet/`` is stdlib-only and never imports agent_ratchet; the root suite imports it from source through this
module only, and never from an installed pack directory.
"""

from __future__ import annotations

import importlib
import importlib.util
import os
import subprocess
import sys
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[1]
FLEET_SRC = ROOT / "fleet" / "src"
_FIXTURES_FILE = ROOT / "fleet" / "tests" / "classify_fixtures.py"


def guard_fleet() -> ModuleType:
    """Import `guard_fleet` from `<root>/fleet/src` (put at `sys.path[0]` once) and return the package."""
    src = str(FLEET_SRC)
    if src not in sys.path:
        sys.path.insert(0, src)
    return importlib.import_module("guard_fleet")


guard_fleet()

from guard_fleet.classify.tree import SourceTree, _scripts  # noqa: E402


def _load_fixtures() -> ModuleType:
    spec = importlib.util.spec_from_file_location("fleet_classify_fixtures", _FIXTURES_FILE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# The fleet suite's own in-memory tree builder (R23.3): no second builder lives in the root suite. Keys are the
# tree's real form (`src/agent_ratchet/a.py`); a cli stub is added unless the files bring their own.
tree_from = _load_fixtures().tree_from


def _clean_git_env() -> dict[str, str]:
    return {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}


def _git(root: Path, *args: str, input: bytes | None = None) -> bytes:
    return subprocess.run(
        ["git", "-c", "maintenance.auto=false", "-c", "gc.auto=0", "-C", str(root), *args],
        input=input, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=_clean_git_env(), check=True, timeout=60,
    ).stdout


def load_tree_from_worktree(root: Path) -> SourceTree:
    """The index state of `src/` under `root` as a SourceTree (same shape as `classify.tree.load_tree`).

    Reads `git ls-files -s -z src/`: the staged blob of each tracked path and its mode. Untracked files are never
    seen; `[project.scripts]` comes from `root/pyproject.toml`.
    """
    modes: dict[str, str] = {}
    blobs: list[tuple[str, str]] = []
    for entry in _git(root, "ls-files", "-s", "-z", "--", "src/").split(b"\0"):
        if not entry:
            continue
        meta, _, raw_path = entry.partition(b"\t")
        mode, oid, _stage = meta.decode("ascii").split(" ")
        path = raw_path.decode("utf-8", errors="surrogateescape")
        modes[path] = mode
        if mode != "160000":   # a gitlink has no blob here
            blobs.append((path, oid))
    files: dict[str, bytes] = {}
    if blobs:
        out = _git(root, "cat-file", "--batch", input="".join(f"{oid}\n" for _, oid in blobs).encode("ascii"))
        pos = 0
        for path, oid in blobs:
            eol = out.index(b"\n", pos)
            header = out[pos:eol].decode("ascii").split(" ")
            assert header[0] == oid and header[1] == "blob", (path, header)
            start = eol + 1
            end = start + int(header[2])
            files[path] = out[start:end]
            pos = end + 1
    pyproject = (root / "pyproject.toml").read_bytes()
    return SourceTree("WORKTREE", files, modes, _scripts(pyproject, "WORKTREE"), pyproject)
