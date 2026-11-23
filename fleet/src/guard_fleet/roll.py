"""Roll steps 1-6 for one consumer: preflight, base, worktree, C1, C2, gates; stateless resume (spec 6.7, 6.11)."""

from __future__ import annotations

import dataclasses
import os
import re
import shutil
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Mapping

from .config import Consumer, FleetConfig
from .deps import Deps
from .env import commit_env
from .gates import GateResult, run_gates
from .gh import Gh, GhAuthError, GhError, GhNetworkError
from .git import (Git, GitError, GitNetworkError, fetch_default, has_commit, origin_url, rev_parse, show_bytes,
                  status_porcelain)
from .ledger import GATES, Ledger, Record
from .lockfile import LockParseError, LockSpec, parse_lock, render_lock
from .names import branch_for, worktree_for
from .pins import PinError, pin_test_hardcodes, rewrite_pin
from .plan import PlanRow
from .proc import low_priority_prefix
from .target import Target

PIN_TEST = "tests/ci/test_guard_pin.py"
CLEANUP = "guard-fleet cleanup"
UV_LOCK_TIMEOUT = 900
HOOK_NAMES = frozenset({
    "applypatch-msg", "pre-applypatch", "post-applypatch", "pre-commit", "pre-merge-commit",
    "prepare-commit-msg", "commit-msg", "post-commit", "pre-rebase", "post-checkout", "post-merge",
    "pre-push", "pre-receive", "update", "proc-receive", "post-receive", "post-update",
    "reference-transaction", "push-to-checkout", "pre-auto-gc", "post-rewrite", "sendemail-validate",
    "fsmonitor-watchman", "p4-changelist", "p4-prepare-changelist", "p4-post-changelist", "p4-pre-submit",
    "post-index-change"})
_ORIGIN = re.compile(r"(?:git@github\.com:|ssh://git@github\.com/|https://github\.com/)"
                     r"([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?/?")


@dataclass
class RollContext:
    deps: Deps
    git: Git
    gh: Gh
    mirror: Path
    cfg: FleetConfig
    target: Target
    ledger: Ledger
    lock_update: bool
    child_env: Mapping[str, str]


@dataclass(frozen=True)
class Rolled:
    short: str
    state: Literal["GATED", "BLOCKED"]
    step: str
    reason: str
    base: str | None
    head: str | None
    attempt: str | None
    hooks: str
    gates: Mapping[str, tuple[str, str]]   # gate -> (verdict, log path)
    worktree: Path | None
    manual_step: str | None


class _Blocked(Exception):
    def __init__(self, step: str, reason: str, *, manual_step: str | None = None, argv: tuple[str, ...] | None = None,
                 rc: int | None = None, log: Path | None = None) -> None:
        super().__init__(reason)
        self.step, self.reason, self.manual_step = step, reason, manual_step
        self.argv, self.rc, self.log = argv, rc, log


def normalise_origin(url: str) -> str | None:
    """`owner/repo` of a github.com remote in scp, ssh:// or https form; None for anything else."""
    m = _ORIGIN.fullmatch(url.strip())
    return m.group(1) if m else None


def hooks_line(git: Git, worktree: Path) -> str:
    r = git(worktree, "rev-parse", "--path-format=absolute", "--git-path", "hooks", check=False)
    hooks = Path(r.text.strip()) if r.rc == 0 and r.text.strip() else None
    if hooks is None or not hooks.is_dir():
        return "hooks: none"
    if not any(f.name in HOOK_NAMES and f.is_file() and os.access(f, os.X_OK) for f in hooks.iterdir()):
        return "hooks: none"
    return "hooks: worktree" if hooks.resolve().is_relative_to(worktree.resolve()) else "hooks: main checkout"


def _worktrees(git: Git, repo: Path) -> list[dict[str, str]]:
    entries: list[dict[str, str]] = []
    for block in git(repo, "worktree", "list", "--porcelain").text.split("\n\n"):
        entry: dict[str, str] = {}
        for line in block.splitlines():
            key, _, value = line.partition(" ")
            if key:
                entry[key] = value
        if "worktree" in entry:
            entries.append(entry)
    return entries


class _Roll:
    def __init__(self, ctx: RollContext, consumer: Consumer, row: PlanRow, *, require_lock_update: bool) -> None:
        self.ctx, self.c, self.row = ctx, consumer, row
        self.require_lock_update = require_lock_update
        self.version = ".".join(str(n) for n in ctx.target.version)
        self.tag = ctx.target.tag
        self.t = ctx.target.sha
        self.branch = branch_for(self.version)
        self.wt = worktree_for(ctx.cfg, consumer, self.version)
        self.base: str | None = None
        self.attempt: str | None = None
        self.hooks = ""
        self.step = "preflight"
        self.pending: list[Record] = []
        self.c1_msg = f"build(deps): pin agent-ratchet v{self.version} in dev dependencies"
        self.c2_msg = f"chore(guard): bump agent-ratchet to v{self.version} ({self.t})"
        self.has_c1 = consumer.pin_kind != "none"

    # -- ledger ----------------------------------------------------------------

    def log_path(self, step: str) -> Path:
        return self.ctx.deps.dirs.gate_log(self.tag, self.c.short, step)

    def record(self, step: str, *, argv: tuple[str, ...] | None = None, rc: int | None = 0, head: str | None = None,
               log: Path | None = None, detail: Mapping[str, object] | None = None) -> None:
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.ctx.deps.clock.wall()))
        rec = Record(ts, self.attempt or "", self.c.short, step, argv, rc, self.base or self.row.d, head,
                     None if log is None else str(log), dict(detail or {}))
        if self.attempt is None:
            self.pending.append(rec)   # steps 1-2 run before the attempt opens (spec 6.7)
        else:
            self.ctx.ledger.record(rec)

    def open_attempt(self) -> None:
        if self.attempt is None:
            self.attempt = self.ctx.ledger.start_attempt(self.c.short, self.row.d or "")
            for rec in self.pending:
                self.ctx.ledger.record(dataclasses.replace(rec, attempt=self.attempt))
            self.pending.clear()

    def blocked(self, b: _Blocked, *, head: str | None = None) -> Rolled:
        self.open_attempt()
        self.record(b.step, argv=b.argv, rc=1 if b.rc is None else b.rc, log=b.log,
                    detail={"reason": b.reason, **({"manual_step": b.manual_step} if b.manual_step else {})})
        assert self.attempt is not None
        self.ctx.ledger.end_attempt(self.attempt, self.c.short, head=head, ok=False)
        return Rolled(self.c.short, "BLOCKED", b.step, b.reason, self.base, head, self.attempt, self.hooks, {},
                      self.wt if self.wt.exists() else None, b.manual_step)

    # -- driver ----------------------------------------------------------------

    def run(self) -> Rolled:
        try:
            self.preflight()
            self.step = "base"
            self.find_base()
            self.open_attempt()
            self.record("base", detail={"p": self.row.p, "extras": self.row.extras})
            self.step = "worktree"
            done = self.worktree()
            if (self.require_lock_update and not self.ctx.lock_update
                    and done < (2 if self.has_c1 else 1)):   # before any write: C2 would be refused (spec 6.11)
                raise _Blocked("c2", "c2: the guard.lock commit needs the lock-update variable set by the "
                               "operator; land carries it only with --rebuild",
                               manual_step=f"guard-fleet release {self.tag}")
            if self.has_c1 and done == 0:
                self.step = "c1"
                self.c1()
                done = 1
            if done < (2 if self.has_c1 else 1):
                self.step = "c2"
                self.c2()
            head = rev_parse(self.ctx.git, self.wt, "HEAD")
            if head is None:
                raise _Blocked(self.step, f"{self.step}: HEAD of {self.wt} is unreadable")
            self.step = "gates"
            assert self.base is not None and self.attempt is not None and self.row.p is not None
            results = run_gates(self.ctx, self.c, base=self.base, head=head, worktree=self.wt, attempt=self.attempt,
                                extras=self.row.extras, p=self.row.p)
        except _Blocked as b:
            return self.blocked(b)
        except (GhAuthError, GhNetworkError, GitNetworkError):
            self.close_failed()
            raise
        except (GhError, GitError, OSError) as exc:
            return self.blocked(_Blocked(self.step, f"{self.step}: {exc}"))
        return self.gated(head, results)

    def gated(self, head: str, results: list[GateResult]) -> Rolled:
        """GATED iff all nine gates ran and none FAILed; the attempt ends ok exactly then."""
        assert self.attempt is not None
        failed = [g for g in results if g.verdict == "FAIL"]
        ok = not failed and tuple(g.gate for g in results) == GATES
        self.ctx.ledger.end_attempt(self.attempt, self.c.short, head=head, ok=ok)
        gates = {g.gate: (g.verdict, str(g.log)) for g in results}
        if ok:
            return Rolled(self.c.short, "GATED", "gates", "", self.base, head, self.attempt, self.hooks, gates,
                          self.wt, None)
        step, reason = (failed[0].gate, failed[0].reason) if failed else ("gates", "gates: incomplete gate table")
        return Rolled(self.c.short, "BLOCKED", step, reason, self.base, head, self.attempt, self.hooks, gates,
                      self.wt, None)

    def close_failed(self) -> None:
        self.open_attempt()
        assert self.attempt is not None
        self.ctx.ledger.end_attempt(self.attempt, self.c.short, head=None, ok=False)

    # -- 1. preflight ----------------------------------------------------------

    def preflight(self) -> None:
        ctx, c = self.ctx, self.c

        def miss(reason: str) -> _Blocked:
            return _Blocked("preflight", f"preflight: {reason}")

        if not c.dir.is_dir() or ctx.git(c.dir, "rev-parse", "--git-dir", check=False).rc != 0:
            raise miss(f"{c.dir} is not a git repository")
        url = origin_url(ctx.git, c.dir)
        if url is None or normalise_origin(url) != c.slug:
            raise miss(f"origin {url!r} does not match {c.slug}")
        live = ctx.gh.default_branch(c.slug)
        if live != c.default_branch:
            raise miss(f"default branch {c.default_branch!r} differs from GitHub's {live!r}")
        path = ctx.child_env.get("PATH", "")
        for need in (*c.hook_needs, "uv", "uvx", "python3"):
            if "/" in need:
                if not (os.path.isfile(need) and os.access(need, os.X_OK)):
                    raise miss(f"{need} is not an executable file")
            elif shutil.which(need, path=path) is None:
                raise miss(f"{need} not found on the subprocess PATH")
        if c.node_modules and not (c.dir / "node_modules").exists():
            raise miss(f"node_modules target {c.dir / 'node_modules'} does not exist")
        if not ctx.gh.merge_commit_allowed(c.slug):
            raise miss(f"merge commits are not allowed on {c.slug}")
        self.record("preflight", detail={"checks": "ok"})

    # -- 2. base ---------------------------------------------------------------

    def find_base(self) -> None:
        ctx, c, row = self.ctx, self.c, self.row
        fetch_default(ctx.git, c.dir, c.default_branch)
        if not row.d or not has_commit(ctx.git, c.dir, row.d):
            raise _Blocked("base", f"base: D {row.d!r} is not in the clone after fetching {c.default_branch}")
        raw = show_bytes(ctx.git, c.dir, row.d, "guard.lock")
        if raw is None:
            raise _Blocked("base", "base: guard.lock is missing at BASE")
        try:
            spec = parse_lock(raw)
        except LockParseError as exc:
            raise _Blocked("base", f"base: guard.lock at BASE: {exc}") from exc
        if row.p is None or spec != LockSpec(row.p, row.extras):
            raise _Blocked("base", f"base: guard.lock at BASE is {spec}, the plan says {row.p} / {row.extras}")
        self.base = row.d

    # -- 3. worktree and resume --------------------------------------------------

    def dirt(self) -> set[str]:
        out = set()
        for entry in status_porcelain(self.ctx.git, self.wt):
            if self.c.node_modules and entry == "?? node_modules":
                continue   # the fleet's own symlink
            out.add(entry[3:])
        return out

    def worktree(self) -> int:
        """Create or resume W; returns how many of the expected commits already exist."""
        ctx, c = self.ctx, self.c
        assert self.base is not None
        exists = rev_parse(ctx.git, c.dir, f"refs/heads/{self.branch}") is not None
        if exists or self.wt.exists() or self.registered() is not None:
            done = self.resume()
            self.hooks = hooks_line(ctx.git, self.wt)
            return done
        self.wt.parent.mkdir(parents=True, exist_ok=True)
        res = ctx.git(c.dir, "worktree", "add", "--no-track", "-b", self.branch, str(self.wt), self.base)
        dirt = status_porcelain(ctx.git, self.wt)
        if dirt:
            raise _Blocked("worktree", "worktree: the fresh checkout is not clean (case-colliding paths?): "
                           + ", ".join(e[3:] for e in dirt), argv=res.argv)
        if c.node_modules and not os.path.lexists(self.wt / "node_modules"):
            os.symlink(c.dir / "node_modules", self.wt / "node_modules")
        self.hooks = hooks_line(ctx.git, self.wt)
        self.record("worktree", argv=res.argv, detail={"branch": self.branch, "path": str(self.wt)})
        return 0

    def registered(self) -> dict[str, str] | None:
        want = self.wt.resolve()
        return next((e for e in _worktrees(self.ctx.git, self.c.dir) if Path(e["worktree"]).resolve() == want), None)

    def expected_subjects(self) -> list[str]:
        return ([self.c1_msg] if self.has_c1 else []) + [self.c2_msg]

    def resume(self) -> int:
        ctx, row = self.ctx, self.row
        entry = self.registered()
        if entry is not None and entry.get("locked", "").startswith("initializing"):
            raise _Blocked("worktree", f"worktree: {self.wt} is locked as initializing",
                           manual_step=f"git worktree unlock {self.wt}, then {CLEANUP}")
        if entry is not None and entry.get("branch") != f"refs/heads/{self.branch}":
            raise _Blocked("worktree", f"worktree: {self.wt} has {entry.get('branch', 'a detached HEAD')} "
                           f"checked out, expected refs/heads/{self.branch}")
        if rev_parse(ctx.git, self.c.dir, f"refs/heads/{self.branch}") is None:
            raise _Blocked("worktree", f"worktree: {self.wt} exists but branch {self.branch} does not")
        merge_base = ctx.git(self.c.dir, "merge-base", self.branch, row.d or "", check=False)
        if merge_base.rc != 0 or not merge_base.text.strip():
            raise _Blocked("worktree", f"worktree: branch {self.branch} shares no history with BASE")
        base = merge_base.text.strip()
        subjects = ctx.git(self.c.dir, "log", "--reverse", "--format=%s", f"{base}..{self.branch}").text.splitlines()
        if entry is None:
            if not subjects:
                raise _Blocked("worktree", f"worktree: branch {self.branch} has 0 commits at BASE and no worktree",
                               manual_step=CLEANUP)
            raise _Blocked("worktree", f"worktree: branch {self.branch} has {len(subjects)} commits but "
                           f"{self.wt} is not its registered worktree; resume only runs in the fleet's own worktree",
                           manual_step=CLEANUP)
        expected = self.expected_subjects()
        if subjects != expected[:len(subjects)]:
            raise _Blocked("worktree", f"worktree: {self.branch} holds foreign commits: {subjects!r}")
        dirt = self.dirt()
        if len(subjects) == len(expected):
            if dirt:
                raise _Blocked("worktree", f"worktree: the finished roll has other changes: {sorted(dirt)}")
        elif not subjects and not dirt:
            raise _Blocked("worktree", f"worktree: branch {self.branch} has 0 commits at BASE", manual_step=CLEANUP)
        else:
            self.check_resume_dirt(base, dirt, c1=self.has_c1 and not subjects)
        self.base = base
        self.record("worktree", detail={"resumed": True, "commits": len(subjects), "branch": self.branch,
                                        "path": str(self.wt)})
        return len(subjects)

    def check_resume_dirt(self, base: str, dirt: set[str], *, c1: bool) -> None:
        files = self.c1_files(base) if c1 else self.c2_files()
        allowed = set(files) | ({"uv.lock"} if c1 and self.c.pin_kind == "pyproject" else set())
        if dirt - allowed:
            raise _Blocked("worktree", f"worktree: dirty paths the fleet did not write: {sorted(dirt - allowed)}")
        if c1 and "uv.lock" in dirt:
            # uv lock keeps existing resolutions, so a foreign edit would be committed as the fleet's own
            if (self.wt / "uv.lock").read_bytes() != show_bytes(self.ctx.git, self.wt, base, "uv.lock"):
                raise _Blocked("worktree", "worktree: uv.lock differs from BASE; resume cannot vouch for its bytes",
                               manual_step=CLEANUP)
        for path in sorted(dirt & set(files)):
            try:
                same = (self.wt / path).read_bytes() == files[path]
            except OSError:
                same = False
            if not same:
                raise _Blocked("worktree", f"worktree: {path} does not hold the fleet's bytes")

    # -- 4. C1 -----------------------------------------------------------------

    def c1_files(self, base: str) -> dict[str, bytes]:
        pin_file = self.c.pin_file
        assert pin_file is not None and self.row.p is not None
        test = show_bytes(self.ctx.git, self.wt, base, PIN_TEST)
        if test is not None and pin_test_hardcodes(test, self.row.p):
            raise _Blocked("c1", "c1: pin test hard-codes the SHA; edit it by hand")
        text = show_bytes(self.ctx.git, self.wt, base, pin_file)
        if text is None:
            raise _Blocked("c1", f"c1: {pin_file} is missing at BASE")
        try:
            return {pin_file: rewrite_pin(text, self.row.p, self.t)}
        except PinError as exc:
            raise _Blocked("c1", f"c1: {pin_file}: {exc}") from exc

    def c1(self) -> None:
        ctx, c = self.ctx, self.c
        assert self.base is not None and c.pin_file is not None
        files = self.c1_files(self.base)
        for path, data in files.items():
            (self.wt / path).write_bytes(data)
        paths = [c.pin_file]
        log = self.log_path("c1")
        if c.pin_kind == "pyproject":
            argv = (*low_priority_prefix(), "uv", "lock", "--quiet")
            res = ctx.deps.run(argv, cwd=self.wt, env=ctx.child_env, timeout=UV_LOCK_TIMEOUT, log=log)
            if res.rc != 0:
                raise _Blocked("c1", "c1: uv lock failed (see the step log)", argv=res.argv, rc=res.rc, log=log)
            if not (self.wt / "uv.lock").is_file():
                raise _Blocked("c1", "c1: uv.lock is missing after uv lock")
            paths.append("uv.lock")
        ctx.git(self.wt, "add", "--", *paths)
        if self.dirt() != set(paths):
            raise _Blocked("c1", f"c1: changed paths {sorted(self.dirt())} differ from {sorted(paths)}")
        self.commit("c1", self.c1_msg, lock_update=False, log=log)

    # -- 5. C2 -----------------------------------------------------------------

    def c2_files(self) -> dict[str, bytes]:
        shim = show_bytes(self.ctx.git, self.ctx.mirror, self.t, "consumer/guard")
        if shim is None:
            raise _Blocked("c2", f"c2: consumer/guard is missing at {self.tag}")
        return {"guard.lock": render_lock(self.t, self.row.extras), "scripts/guard": shim}

    def c2(self) -> None:
        ctx = self.ctx
        files = self.c2_files()
        (self.wt / "scripts").mkdir(exist_ok=True)
        for path, data in files.items():
            (self.wt / path).write_bytes(data)
        (self.wt / "scripts" / "guard").chmod(0o755)
        ctx.git(self.wt, "add", "--", "guard.lock", "scripts/guard")
        mode = ctx.git(self.wt, "ls-files", "-s", "scripts/guard").text.split(maxsplit=1)[:1]
        if mode != ["100755"]:
            raise _Blocked("c2", f"c2: scripts/guard has mode {mode}, expected 100755")
        dirt = self.dirt()
        if "guard.lock" not in dirt or not dirt <= set(files):
            raise _Blocked("c2", f"c2: changed paths {sorted(dirt)} differ from {sorted(files)}")
        self.hooks = hooks_line(ctx.git, self.wt)
        self.commit("c2", self.c2_msg, lock_update=ctx.lock_update, log=self.log_path("c2"))

    def commit(self, step: str, message: str, *, lock_update: bool, log: Path) -> None:
        ctx = self.ctx
        env = commit_env(ctx.child_env, self.c.commit_env, lock_update=lock_update)
        res = ctx.git(self.wt, "commit", "-q", "-m", message, check=False, env=env, log=log)
        if res.rc != 0:
            raise _Blocked(step, f"{step}: hook refused", argv=res.argv, rc=res.rc, log=log)
        head = rev_parse(ctx.git, self.wt, "HEAD")
        self.record(step, argv=res.argv, rc=0, head=head, log=log,
                    detail={"hooks": self.hooks} if step == "c2" else {})


def prepare(ctx: RollContext, consumer: Consumer, row: PlanRow, *, require_lock_update: bool = False) -> Rolled:
    """Steps 1-6. GATED (step "gates") iff no gate FAILs; a FAIL is BLOCKED with the first failing gate as step.

    require_lock_update: a C2 still to commit without ctx.lock_update is BLOCKED before any write, with
    `guard-fleet release <tag>` as its next step (the consumer's lock policy would refuse that commit)."""
    return _Roll(ctx, consumer, row, require_lock_update=require_lock_update).run()
