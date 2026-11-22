"""Test doubles: a routed runner, a controllable clock and a deps factory."""

from __future__ import annotations

import io
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping, Sequence

from guard_fleet import proc
from guard_fleet.deps import ConfirmResult, Deps
from guard_fleet.dirs import Dirs
from guard_fleet.proc import Result


@dataclass
class Route:
    match: tuple[str, ...] | Callable[[tuple[str, ...]], bool]
    rc: int = 0
    stdout: bytes = b""
    stderr: bytes = b""
    effect: Callable[[tuple[str, ...], Path, Mapping[str, str]], Result | None] | None = None

    def matches(self, argv: tuple[str, ...]) -> bool:
        if callable(self.match):
            return bool(self.match(argv))
        return argv[: len(self.match)] == self.match


class FakeRunner:
    def __init__(self, routes: list[Route], real: frozenset[str] = frozenset({"git"})) -> None:
        self.routes = routes
        self.real = real
        self.calls: list[tuple[tuple[str, ...], Path, dict[str, str]]] = []

    def __call__(self, argv: Sequence[str], *, cwd: Path, env: Mapping[str, str], timeout: float,
                 input: bytes | None = None, log: Path | None = None) -> Result:
        args = tuple(argv)
        prefix = proc.low_priority_prefix()
        for p in (prefix, ("nice", "-n", "15")):
            if p and args[: len(p)] == p:
                args = args[len(p):]
                break
        self.calls.append((args, cwd, dict(env)))
        if args and args[0] in self.real:
            return proc.run(args, cwd=cwd, env=env, timeout=timeout, input=input, log=log)
        for route in self.routes:
            if route.matches(args):
                if route.effect is not None:
                    got = route.effect(args, cwd, env)
                    if got is not None:
                        return got
                return Result(args, route.rc, route.stdout, route.stderr, False)
        raise AssertionError(f"unrouted argv: {args!r}")


class FakeClock:
    def __init__(self, start_mono: float = 1000.0, start_wall: float = 1_700_000_000.0) -> None:
        self._mono = start_mono
        self._wall = start_wall

    def monotonic(self) -> float:
        return self._mono

    def wall(self) -> float:
        return self._wall

    def advance(self, seconds: float, *, wall_only: bool = False) -> None:
        self._wall += seconds
        if not wall_only:
            self._mono += seconds


def make_deps(tmp_home: Path, routes=(), confirm=None, environ=None) -> Deps:
    clock = FakeClock()
    return Deps(
        run=FakeRunner(list(routes)),
        confirm=confirm or (lambda _reason: ConfirmResult("approved", "")),
        clock=clock,
        sleep=clock.advance,
        environ=dict(os.environ) if environ is None else environ,
        dirs=Dirs(tmp_home),
        out=io.StringIO(),
        err=io.StringIO(),
        platform="linux",
    )
