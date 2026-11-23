"""`release --diff`: tools/differential_findings.py at T, old pin vs new, informational only (spec 6.7, 3.4)."""

from __future__ import annotations

import re
import shutil
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

from .git import GitError, show_bytes
from .lockfile import _SPEC_BASE, spec_url
from .proc import low_priority_prefix

if TYPE_CHECKING:
    from .config import Consumer
    from .roll import RollContext

TOOL = "tools/differential_findings.py"
PER_COMMAND_TIMEOUT = "600"
# the 4.x legacy side (spec 3.4); `--new-from` is the tool's uvx --from spec (differential_findings.py:144 at c305de7)
LEGACY_CMD = "uvx --quiet --from " + _SPEC_BASE + "@{p} agent-ratchet --expect-sha {p}"
_DIFFERING = re.compile(r"^(\d+) differing case\(s\)$")


def _one_line(text: str, limit: int = 200) -> str:
    return " ".join(text.split())[:limit]


def run_diff(ctx: RollContext, consumer: Consumer, *, base: str, p: str, t: str, extras: str, worktree: Path,
             budget_s: int = 1800) -> str:
    """A one-line summary; a tool error or timeout is reported, never raised and never a gate."""
    try:
        tool = show_bytes(ctx.git, ctx.mirror, t, TOOL)
    except (GitError, OSError) as exc:
        return f"diff: cannot read {TOOL} at T: {_one_line(str(exc))}"
    if tool is None:
        return f"diff: {TOOL} is missing at {ctx.target.tag}"
    if extras != "none" and b'"--new-from"' not in tool:
        return "diff: EXTRAS not supported by the tool"
    cdir = ctx.deps.dirs.consumer_dir(ctx.target.tag, consumer.short)
    out = cdir / "differential"
    tmp = Path(tempfile.mkdtemp(prefix="guard-fleet-diff-"))   # outside every repo; -I keeps cwd off sys.path
    try:
        cdir.mkdir(parents=True, exist_ok=True, mode=0o700)
        script = tmp / "differential_findings.py"
        script.write_bytes(tool)
        argv = (*low_priority_prefix(), "python3", "-I", str(script), "--consumer", str(worktree),
                "--legacy-ref", base, "--guard-sha", t, "--legacy-cmd", LEGACY_CMD.format(p=p),
                "--commits", "30", "--timeout", PER_COMMAND_TIMEOUT, "--out", str(out))
        if extras != "none":
            argv += ("--new-from", spec_url(t, extras))
        # --timeout bounds each command the tool runs; the budget bounds the whole tool
        res = ctx.deps.run(argv, cwd=worktree, env=ctx.child_env, timeout=budget_s, log=cdir / "differential.log")
    except OSError as exc:
        return f"diff: tool error: {_one_line(str(exc))}"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    if res.timed_out:
        return f"diff: timed out after {budget_s} s"
    lines = (res.stdout + b"\n" + res.stderr).decode("utf-8", errors="replace").splitlines()
    errors = [line for line in lines if line.startswith("ERROR:")]
    if res.rc not in (0, 1) or errors:
        detail = errors[0] if errors else next((line for line in reversed(lines) if line.strip()), "")
        return f"diff: tool error (rc {res.rc}): {_one_line(detail)}"
    if res.rc == 0:
        return f"diff: no differences ({out})"
    counts = [m.group(1) for m in map(_DIFFERING.match, lines) if m]
    if not counts:
        return f"diff: tool error (rc 1) without a summary line, see {out}"
    return f"diff: {counts[-1]} differing case(s), see {out}"
