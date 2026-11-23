"""The local bare mirror of the upstream repository."""

from __future__ import annotations

import fcntl
import os
from datetime import datetime, timezone
from pathlib import Path

from .deps import Deps
from .exits import UsageError
from .git import Git

UPSTREAM_URL = "https://github.com/dpopek/agent-ratchet"
MIRROR_REFSPECS = ("+refs/heads/main:refs/heads/main", "+refs/tags/*:refs/tags/*")

_LOCK_POLL = 0.5
_LOCK_WAIT = 60.0


def _lock_exclusive(deps: Deps, fd: int) -> None:
    deadline = deps.clock.monotonic() + _LOCK_WAIT
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except BlockingIOError:
            if deps.clock.monotonic() >= deadline:
                raise UsageError("mirror lock busy") from None
            deps.sleep(_LOCK_POLL)


def refresh_mirror(deps: Deps, git: Git) -> Path:
    dirs = deps.dirs
    dirs.state.mkdir(parents=True, exist_ok=True)
    fd = os.open(dirs.mirror_lock, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        _lock_exclusive(deps, fd)
        if not dirs.mirror.exists():
            git(dirs.state, "clone", "--bare", UPSTREAM_URL, str(dirs.mirror))
            git(dirs.mirror, "config", "maintenance.auto", "false")
            git(dirs.mirror, "config", "gc.auto", "0")
        git(dirs.mirror, "fetch", "origin", *MIRROR_REFSPECS)
        stamp = datetime.fromtimestamp(deps.clock.wall(), timezone.utc).isoformat(timespec="seconds")
        dirs.mirror_fetched.write_text(stamp + "\n", encoding="utf-8")
    finally:
        os.close(fd)  # drops the flock
    return dirs.mirror


def mirror_readonly(deps: Deps) -> tuple[Path, str]:
    dirs = deps.dirs
    try:
        stamp = dirs.mirror_fetched.read_text(encoding="utf-8").strip()
    except OSError:
        stamp = ""
    if not dirs.mirror.is_dir() or not stamp:
        raise UsageError("no mirror yet; run guard-fleet plan once without a busy lock")
    return dirs.mirror, stamp
