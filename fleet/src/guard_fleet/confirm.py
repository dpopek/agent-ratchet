"""Touch ID confirmation: a Swift helper compiled per use, plus the table-then-dialog flow."""

from __future__ import annotations

import importlib.resources
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Mapping, Sequence

from . import proc
from .deps import ConfirmResult, Deps
from .exits import Cancelled, NoHelper
from .proc import Runner

TIMEOUT_S = 600
REASON_MAX = 150
AGENT_SUFFIX = " · from agent shell"
COMPILE_TIMEOUT_S = 300
_NEEDS = "needs macOS with the Xcode Command Line Tools (/usr/bin/swiftc)"


def reason_simple(text: str, *, markers: bool) -> str:
    """Fit text into REASON_MAX characters, cutting the body (never the agent suffix)."""
    suffix = AGENT_SUFFIX if markers else ""
    limit = REASON_MAX - len(suffix)
    if len(text) > limit:
        text = text[: limit - 1] + "…"
    return text + suffix


def reason_text(action: str, tag: str, t: str, rings: Mapping[int, Sequence[str]], *,
                markers: bool) -> str:
    body = f"{action} {tag} ({t[:7]})"
    parts = [f"ring {n} {', '.join(names)}" for n, names in sorted(rings.items()) if names]
    if parts:
        body += ": " + "; ".join(parts)
    return reason_simple(body, markers=markers)


def _last_line(r: proc.Result) -> str:
    lines = (r.stderr + r.stdout).decode("utf-8", errors="replace").strip().splitlines()
    return lines[-1] if lines else f"swiftc exited {r.rc}"


def touch_id(reason: str, *, platform: str = sys.platform, swiftc: Path = Path("/usr/bin/swiftc"),
             run: Runner = proc.run) -> ConfirmResult:
    if platform != "darwin" or not swiftc.exists():
        return ConfirmResult("no_helper", _NEEDS)
    work = Path(tempfile.mkdtemp())
    try:
        work.chmod(0o700)
        src = work / "confirm.swift"
        src.write_bytes((importlib.resources.files("guard_fleet") / "confirm.swift").read_bytes())
        exe = work / "confirm"
        env = {"PATH": "/usr/bin:/bin", "HOME": os.environ.get("HOME", "")}
        built = run([str(swiftc), "-O", "-o", str(exe), str(src)], cwd=work, env=env,
                    timeout=COMPILE_TIMEOUT_S)
        if built.timed_out or built.rc != 0:
            return ConfirmResult("no_helper", "swiftc timed out" if built.timed_out else _last_line(built))
        got = run([str(exe), reason], cwd=work, env=env, timeout=TIMEOUT_S)
        if got.timed_out:
            return ConfirmResult("timeout", f"no answer within {TIMEOUT_S} s")
        if got.rc == 0:
            return ConfirmResult("approved", "")
        if got.rc == 5:
            return ConfirmResult("no_helper", "Touch ID / password policy unavailable")
        return ConfirmResult("cancelled", "confirmation cancelled")
    finally:
        shutil.rmtree(work, ignore_errors=True)


def ask(deps: Deps, table: str, reason: str) -> None:
    deps.out.write(table)
    deps.out.flush()
    result = deps.confirm(reason)
    if result.status == "approved":
        return
    if result.status == "no_helper":
        raise NoHelper(result.detail)
    raise Cancelled(result.detail or result.status)
