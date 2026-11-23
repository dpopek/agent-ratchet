"""The dependency bundle every fleet module receives."""

from __future__ import annotations

import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Literal, Protocol, TextIO

from . import proc
from .dirs import Dirs


class Clock(Protocol):
    def monotonic(self) -> float: ...
    def wall(self) -> float: ...


class SystemClock:
    def monotonic(self) -> float:
        return time.monotonic()

    def wall(self) -> float:
        return time.time()


@dataclass(frozen=True)
class ConfirmResult:
    status: Literal["approved", "cancelled", "timeout", "no_helper"]
    detail: str


@dataclass
class Deps:
    run: proc.Runner
    confirm: Callable[[str], ConfirmResult]
    clock: Clock
    sleep: Callable[[float], None]
    environ: dict[str, str]
    dirs: Dirs
    out: TextIO
    err: TextIO
    platform: str


def _touch_id(reason: str) -> ConfirmResult:
    from . import confirm  # local import: confirm imports ConfirmResult from this module

    return confirm.touch_id(reason)


def default_deps() -> Deps:
    return Deps(
        run=proc.run,
        confirm=_touch_id,
        clock=SystemClock(),
        sleep=time.sleep,
        environ=dict(os.environ),
        dirs=Dirs(Path.home()),
        out=sys.stdout,
        err=sys.stderr,
        platform=sys.platform,
    )
