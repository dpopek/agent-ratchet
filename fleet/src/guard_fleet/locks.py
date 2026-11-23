"""The run lock (flock) and the guard_bump.sh liveness probe."""

from __future__ import annotations

import fcntl
import os
from pathlib import Path
from typing import IO, Mapping

from .proc import Runner


class RunLock:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._fh: IO[bytes] | None = None

    def acquire(self, *, exclusive: bool) -> bool:
        if self._fh is not None:
            raise RuntimeError("lock already held by this object")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fh = open(os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600), "r+b")
        try:
            fcntl.flock(fh, (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB)
        except BlockingIOError:
            fh.close()
            return False
        self._fh = fh
        return True

    def release(self) -> None:
        if self._fh is not None:
            self._fh.close()  # closing drops the flock
            self._fh = None

    def __enter__(self) -> "RunLock":
        if not self.acquire(exclusive=True):
            raise RuntimeError(f"lock busy: {self.path}")
        return self

    def __exit__(self, *exc: object) -> None:
        self.release()


def guard_bump_running(run: Runner, env: Mapping[str, str], cwd: Path) -> bool:
    """True when guard_bump.sh is running; also True on any probe failure (fail closed)."""
    rc = run(("pgrep", "-f", "guard_bump.sh"), cwd=cwd, env=env, timeout=10).rc
    return rc != 1
