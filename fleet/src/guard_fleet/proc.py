"""The single subprocess seam: bounded, stdin-less, killable as a group."""

from __future__ import annotations

import os
import shlex
import shutil
import signal
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping, Sequence


@dataclass(frozen=True)
class Result:
    argv: tuple[str, ...]
    rc: int
    stdout: bytes
    stderr: bytes
    timed_out: bool

    @property
    def text(self) -> str:
        return self.stdout.decode("utf-8", errors="replace")


Runner = Callable[..., Result]


def _append_log(log: Path, r: Result) -> None:
    log.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "ab") as fh:
        fh.write(f"$ {shlex.join(r.argv)}\n".encode())
        fh.write(r.stdout)
        fh.write(r.stderr)
        fh.write(f"rc={r.rc}\n".encode())


def run(argv: Sequence[str], *, cwd: Path, env: Mapping[str, str], timeout: float,
        input: bytes | None = None, log: Path | None = None) -> Result:
    args = tuple(argv)
    try:
        p = subprocess.Popen(
            args, cwd=cwd, env=dict(env),
            stdin=subprocess.DEVNULL if input is None else subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    except FileNotFoundError as exc:
        result = Result(args, 127, b"", str(exc).encode(), False)
    else:
        try:
            out, err = p.communicate(input, timeout=timeout)
            result = Result(args, p.returncode, out, err, False)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            out, err = p.communicate()
            result = Result(args, 124, out or b"", err or b"", True)
    if log is not None:
        _append_log(log, result)
    return result


def low_priority_prefix(platform: str = sys.platform,
                        which: Callable[[str], str | None] = shutil.which) -> tuple[str, ...]:
    if platform == "darwin" and which("taskpolicy") and which("nice"):
        return ("taskpolicy", "-c", "utility", "-d", "utility", "nice", "-n", "15")
    if which("nice"):
        return ("nice", "-n", "15")
    return ()
