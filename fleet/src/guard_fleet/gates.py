"""Roll step 6: nine local gates, each with its own subprocess or in-process check, rc, ledger record and log."""

from __future__ import annotations

import os
import tempfile
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Literal, Mapping

from .env import g6_env
from .git import rev_parse, show_bytes, status_porcelain
from .ledger import Record
from .lockfile import spec_url
from .proc import Result, low_priority_prefix

if TYPE_CHECKING:
    from .config import Consumer
    from .roll import RollContext

GATE_TIMEOUT = 1800
TAIL_LINES = 30
PIN_TEST = "tests/ci/test_guard_pin.py"
NO_LOG = Path(os.devnull)   # in-process checks run outside run_gates have no log of their own


@dataclass(frozen=True)
class GateResult:
    gate: str
    verdict: Literal["PASS", "FAIL", "n/a"]
    reason: str
    argv: tuple[str, ...] | None
    rc: int | None
    log: Path


def uv_cache_dir(env: Mapping[str, str], fallback: Path) -> Path:
    """The operator's uv cache, pinned before G6 moves HOME and XDG_CACHE_HOME to a temp dir."""
    if env.get("UV_CACHE_DIR"):
        return Path(env["UV_CACHE_DIR"])
    if env.get("XDG_CACHE_HOME"):
        return Path(env["XDG_CACHE_HOME"]) / "uv"
    if env.get("HOME"):
        return Path(env["HOME"]) / ".cache" / "uv"
    return fallback


def junit_counts(path: Path) -> tuple[int, int, int, int] | None:
    """(tests, skipped, failures, errors) summed over every testsuite; None when the report is unreadable."""
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError):
        return None
    suites = [root] if root.tag == "testsuite" else root.findall("testsuite") if root.tag == "testsuites" else []
    if not suites:
        return None
    totals = [0, 0, 0, 0]
    for suite in suites:
        for i, key in enumerate(("tests", "skipped", "failures", "errors")):
            value = suite.get(key, "0")
            if not value.isdigit():
                return None
            totals[i] += int(value)
    return totals[0], totals[1], totals[2], totals[3]


class _Gates:
    def __init__(self, ctx: RollContext, consumer: Consumer, *, base: str, head: str, worktree: Path, attempt: str,
                 extras: str, p: str) -> None:
        self.ctx, self.c = ctx, consumer
        self.base, self.head, self.wt, self.attempt, self.extras, self.p = base, head, worktree, attempt, extras, p
        self.t = ctx.target.sha
        self.tag = ctx.target.tag
        self.cdir = ctx.deps.dirs.consumer_dir(self.tag, consumer.short)
        self.range = f"{base}..{head}"
        self.trusted: Path | None = None
        self.trusted_error = ""

    def log(self, gate: str) -> Path:
        return self.ctx.deps.dirs.gate_log(self.tag, self.c.short, gate)

    # -- harness -----------------------------------------------------------------

    def run(self) -> list[GateResult]:
        from . import api_compat, shape   # both import GateResult from this module

        self.cdir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.write_trusted()
        checks: list[tuple[str, Callable[[], GateResult]]] = [
            ("G1", self.g1), ("G2", self.g2), ("G3", self.g3), ("G4", self.g4), ("G5", self.g5), ("G6", self.g6),
            ("G7", lambda: api_compat.check(self.ctx.git, self.wt, self.ctx.mirror, base=self.base, t=self.t)),
            ("G8", lambda: shape.check(self.ctx.git, self.wt, self.ctx.mirror, self.c, base=self.base,
                                       head=self.head, p=self.p, t=self.t, extras=self.extras)),
            ("G9", self.g9)]
        results = []
        for gate, check in checks:   # every gate runs: a FAIL skips nothing, so the table is complete
            try:
                res = check()
            except Exception as exc:   # fail closed: a gate that cannot decide is a FAIL
                res = GateResult(gate, "FAIL", f"{gate}: {type(exc).__name__}: {exc}", None, None, self.log(gate))
            res = replace(res, gate=gate, log=self.log(gate))
            observed, res = self.check_head(res)
            self.finish(res, observed)
            results.append(res)
        return results

    def check_head(self, res: GateResult) -> tuple[str | None, GateResult]:
        """Spec 6.7: after each gate HEAD must still be H, otherwise that gate FAILs."""
        try:
            now = rev_parse(self.ctx.git, self.wt, "HEAD")
        except Exception as exc:
            return None, replace(res, verdict="FAIL", reason=f"HEAD moved: cannot read HEAD ({exc}); {res.reason}")
        if now != self.head:
            return now, replace(res, verdict="FAIL", reason=f"HEAD moved: HEAD is {now}, expected {self.head}; "
                                                            f"{res.reason}")
        return now, res

    def finish(self, res: GateResult, observed: str | None) -> None:
        res.log.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(res.log, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as fh:
            fh.write(f"{res.gate} {res.verdict}: {res.reason}\n")
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.ctx.deps.clock.wall()))
        self.ctx.ledger.record(Record(ts, self.attempt, self.c.short, res.gate, res.argv, res.rc, self.base, observed,
                                      str(res.log), {"verdict": res.verdict, "reason": res.reason}))
        if res.verdict == "FAIL":
            tail = res.log.read_text(encoding="utf-8", errors="replace").splitlines()[-TAIL_LINES:]
            err = self.ctx.deps.err
            err.write(f"{self.c.short}: {res.gate} FAIL: {res.reason}\n  log: {res.log}\n")
            err.write("".join(f"  | {line}\n" for line in tail))

    def command(self, gate: str, argv: tuple[str, ...], judge: Callable[[Result], str | None], *,
                env: Mapping[str, str] | None = None) -> GateResult:
        full = (*low_priority_prefix(), *argv)
        res = self.ctx.deps.run(full, cwd=self.wt, env=self.ctx.child_env if env is None else env,
                                timeout=GATE_TIMEOUT, log=self.log(gate))
        if res.timed_out:
            return GateResult(gate, "FAIL", f"{gate}: timed out after {GATE_TIMEOUT} s", full, res.rc, self.log(gate))
        why = judge(res)
        if why is not None:
            return GateResult(gate, "FAIL", f"{gate}: {why}", full, res.rc, self.log(gate))
        return GateResult(gate, "PASS", f"{gate}: rc 0", full, res.rc, self.log(gate))

    @staticmethod
    def rc_zero(res: Result) -> str | None:
        return None if res.rc == 0 else f"rc {res.rc}"

    # -- G1, G2: the base judge ----------------------------------------------------

    def write_trusted(self) -> None:
        """`git show BASE:scripts/guard` into the fleet's state dir, outside the worktree (spec 6.7)."""
        try:
            shim = show_bytes(self.ctx.git, self.wt, self.base, "scripts/guard")
            if shim is None:
                self.trusted_error = "scripts/guard is missing at BASE"
                return
            path = self.cdir / "trusted-guard"
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o700)
            with os.fdopen(fd, "wb") as fh:
                fh.write(shim)
            os.chmod(path, 0o700)
            self.trusted = path
        except Exception as exc:
            self.trusted_error = f"cannot write the trusted shim: {type(exc).__name__}: {exc}"

    def judged_by_base(self, gate: str, *args: str) -> GateResult:
        if self.trusted is None:
            return GateResult(gate, "FAIL", f"{gate}: {self.trusted_error}", None, None, self.log(gate))
        return self.command(gate, ("sh", str(self.trusted), "--lock-from", self.base, *args), self.rc_zero)

    def g1(self) -> GateResult:
        return self.judged_by_base("G1", "scan", "--commit-range", self.range)

    def g2(self) -> GateResult:
        return self.judged_by_base("G2", "baseline-integrity", "--require-base-ref", "--enforce-policy-isolation",
                                   "--commit-range", self.range)

    # -- G3-G5: the new shim -------------------------------------------------------

    def g3(self) -> GateResult:
        def judge(res: Result) -> str | None:
            got = res.text.strip()
            if res.rc == 0 and got == self.t:
                return None
            return f"version --sha printed {got[:80]!r} (rc {res.rc}), expected {self.t}"
        return self.command("G3", ("sh", "scripts/guard", "version", "--sha"), judge)

    def g4(self) -> GateResult:
        return self.command("G4", ("sh", "scripts/guard", "scan", "--commit-range", self.range), self.rc_zero)

    def g5(self) -> GateResult:
        return self.command("G5", ("sh", "scripts/guard", "baseline-integrity", "--require-base-ref",
                                   "--enforce-policy-isolation", "--commit-range", self.range), self.rc_zero)

    # -- G6: the pin test ----------------------------------------------------------

    def g6(self) -> GateResult:
        if self.c.pin_kind == "none":
            return GateResult("G6", "n/a", "G6: pin kind none has no pin test", None, None, self.log("G6"))
        if show_bytes(self.ctx.git, self.wt, self.head, PIN_TEST) is None:
            return GateResult("G6", "FAIL", f"G6: pin test missing: {PIN_TEST} is not in the bump", None, None,
                              self.log("G6"))
        xml = self.cdir / "G6.xml"
        xml.unlink(missing_ok=True)   # a stale report must never count
        argv = ("uv", "run", "--isolated", "--no-config", "--no-project", "--with", spec_url(self.t, self.extras),
                "--with", "pytest", "python", "-m", "pytest", "-q", "-p", "no:cacheprovider", "--noconftest",
                "-c", "/dev/null", "--rootdir", ".", "--junitxml", str(xml), PIN_TEST)

        def judge(res: Result) -> str | None:
            counts = junit_counts(xml)
            if counts is None:
                return f"rc {res.rc}, no readable JUnit report"
            tests, skipped, failures, errors = counts
            passed = tests - skipped - failures - errors
            if res.rc == 0 and failures == 0 and errors == 0 and passed >= 1:
                return None
            return (f"rc {res.rc}, {passed} passed of {tests} "
                    f"({skipped} skipped, {failures} failed, {errors} errors); needs rc 0 and 1 passed")

        with tempfile.TemporaryDirectory(prefix="guard-fleet-g6-") as tmp:
            env = g6_env(self.ctx.child_env, Path(tmp),
                         uv_cache=uv_cache_dir(self.ctx.child_env, Path(tmp) / "uv-cache"))
            res = self.command("G6", argv, judge, env=env)
        if res.verdict == "PASS":
            return replace(res, reason=f"G6: {(junit_counts(xml) or (0,))[0]} tests, rc 0")
        return res

    # -- G9: the clean tree --------------------------------------------------------

    def g9(self) -> GateResult:
        dirt = [e for e in status_porcelain(self.ctx.git, self.wt, ignored=False)
                if not (self.c.node_modules and e == "?? node_modules")]
        if dirt:
            return GateResult("G9", "FAIL", "G9: the worktree is not clean: " + ", ".join(dirt), None, None,
                              self.log("G9"))
        return GateResult("G9", "PASS", "G9: clean", None, None, self.log("G9"))


def run_gates(ctx: RollContext, consumer: Consumer, *, base: str, head: str, worktree: Path, attempt: str,
              extras: str, p: str) -> list[GateResult]:
    """G1-G9 in order; each writes its own ledger record and log, and a FAIL prints the log's last 30 lines."""
    return _Gates(ctx, consumer, base=base, head=head, worktree=worktree, attempt=attempt, extras=extras, p=p).run()
