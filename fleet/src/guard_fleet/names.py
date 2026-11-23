"""Fleet branch and worktree names (guard_bump's naming, so its leftovers stay cleanable)."""

from __future__ import annotations

import re
from pathlib import Path

from .config import Consumer, FleetConfig

VERSION_RE = re.compile(r"[0-9]+[.][0-9]+[.][0-9]+")
_BRANCH_PREFIX = "chore/agent-ratchet-"


def _checked(version: str) -> str:
    if not (version.isascii() and VERSION_RE.fullmatch(version)):
        raise ValueError(f"not a X.Y.Z version: {version!r}")
    return version


def branch_for(version: str) -> str:
    return _BRANCH_PREFIX + _checked(version)


def worktree_for(cfg: FleetConfig, consumer: Consumer, version: str) -> Path:
    return cfg.worktree_root / f"{consumer.short}-wt-agent-ratchet-{_checked(version)}"


def parse_fleet_branch(name: str) -> str | None:
    """The version of a fleet branch name; None for every other name (migrate-imports included)."""
    if not name.startswith(_BRANCH_PREFIX):
        return None
    version = name[len(_BRANCH_PREFIX):]
    return version if version.isascii() and VERSION_RE.fullmatch(version) else None


def is_fleet_worktree(cfg: FleetConfig, consumer: Consumer, path: Path, branch: str | None) -> bool:
    """A worktree is the fleet's only when its path and its checked-out branch carry the same version."""
    version = parse_fleet_branch(branch) if branch is not None else None
    return version is not None and path == worktree_for(cfg, consumer, version)
