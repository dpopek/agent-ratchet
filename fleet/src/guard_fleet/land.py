"""Land one consumer: just-in-time publish, fail-closed merge checks, merge, post-merge verify (spec 6.8)."""

from __future__ import annotations

import dataclasses
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Literal, Mapping, Sequence, TypeVar

from . import api_compat, prbody, shape
from .ci import wait_for_ci
from .cleanup import CleanupContext, cleanup_landed, fleet_node_modules, ignored_allowed
from .config import Consumer
from .gate_inputs import AskError, gate_inputs, touches
from .gh import GhNotFound
from .git import GitError, GitNetworkError, fetch_default, is_ancestor, ls_remote, rev_parse, show_bytes, status_porcelain
from .ledger import Record, gated_attempt
from .lockfile import LockParseError, LockSpec, parse_lock, render_lock
from .names import branch_for, parse_fleet_branch, worktree_for
from .roll import RollContext, Rolled
from .target import TargetError, validate_target

GOVERNANCE_JOB = "Agent-Ratchet Governance Gate"
MERGE_STATES_OK = frozenset({"CLEAN", "UNSTABLE", "HAS_HOOKS"})
WALL_GAP_S = 120
POLL_START, POLL_CEILING = 2.0, 30.0
MERGE_READBACK = (2.0, 4.0, 8.0, 16.0, 30.0)
PREMERGE_RERUNS = 3   # premerge re-runs after a quiet wait or a wall-clock gap before land gives up
REBUILD_FLAG = "rebuild:"   # Approval.flags holds f"{REBUILD_FLAG}{short}" for every --rebuild short
_FLEET_PATHS = ("guard.lock", "scripts/guard")

T = TypeVar("T")
State = Literal["LANDED", "BLOCKED", "FAILED", "HELD", "NOT_RUN"]


@dataclass(frozen=True)
class Approval:
    tag: str
    t: str
    heads: Mapping[str, str]
    flags: frozenset[str]

    def covers(self, short: str, head: str, t: str) -> bool:
        return t == self.t and self.heads.get(short) == head


@dataclass(frozen=True)
class Outcome:
    short: str
    state: State
    step: str
    reason: str
    pr_url: str | None
    merge_sha: str | None
    next_command: str | None
    keep_pr_open: bool
    cleanup: tuple[str, ...] = ()
    cleanup_kept: bool = False


class _Miss(Exception):
    """A post-merge verify check that cannot even run."""


class RebuildBlocked(Exception):
    """`rebuild_local` could not prove the local leftovers are only the fleet's: the consumer stays BLOCKED."""


def _version(ctx: RollContext) -> str:
    return ".".join(str(n) for n in ctx.target.version)


class Lander:
    def __init__(self, ctx: RollContext, approval: Approval, login: str, *, running_tag: str = "unknown",
                 running_sha: str = "unknown", evidence: Mapping[str, Sequence[str]] | None = None,
                 deploy_lines: Mapping[str, str] | None = None) -> None:
        self.ctx, self.approval, self.login = ctx, approval, login
        self.running_tag, self.running_sha = running_tag, running_sha
        self.evidence = dict(evidence or {})
        self.deploy_lines = dict(deploy_lines or {})
        self.version = _version(ctx)
        self.branch = branch_for(self.version)
        self.tag, self.t = ctx.target.tag, ctx.target.sha
        self._skew = self._now_skew()
        self._waited = False   # the latest premerge waited for the deploy queue
        self._quiet_deadline: float | None = None   # one ci_wait_min quiet budget per land_consumer

    # -- helpers ---------------------------------------------------------------

    def _now_skew(self) -> float:
        return self.ctx.deps.clock.wall() - self.ctx.deps.clock.monotonic()

    def _drifted(self) -> bool:
        """True when the wall clock moved more than WALL_GAP_S past the monotonic one since the previous check."""
        now = self._now_skew()
        moved = abs(now - self._skew) > WALL_GAP_S
        self._skew = now
        return moved

    def _url(self, c: Consumer) -> str:
        return f"https://github.com/{c.slug}"

    def _remote_ref(self, c: Consumer, ref: str) -> str | None:
        return ls_remote(self.ctx.git, c.dir, self._url(c), ref).get(ref)

    def _lock_at(self, repo: Path, rev: str) -> LockSpec | None:
        raw = show_bytes(self.ctx.git, repo, rev, "guard.lock")
        try:
            return parse_lock(raw) if raw is not None else None
        except LockParseError:
            return None

    def _base_lock(self, c: Consumer, rolled: Rolled) -> LockSpec | None:
        """P and EXTRAS from guard.lock at BASE (roll checked it against the plan); None when unreadable."""
        return self._lock_at(c.dir, rolled.base) if rolled.base else None

    def _record(self, c: Consumer, step: str, *, attempt: str | None, base: str | None, head: str | None,
                detail: Mapping[str, object]) -> None:
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.ctx.deps.clock.wall()))
        self.ctx.ledger.record(Record(ts, attempt or "", c.short, step, None, None, base, head, None, dict(detail)))

    def _outcome(self, c: Consumer, state: State, step: str, reason: str, *, pr_url: str | None = None,
                 merge_sha: str | None = None, next_command: str | None = None,
                 keep_pr_open: bool = False) -> Outcome:
        return Outcome(c.short, state, step, reason, pr_url, merge_sha, next_command, keep_pr_open)

    def _resume(self) -> str:
        return f"guard-fleet land {self.tag}"

    def _close(self, c: Consumer, number: int, step: str, reason: str, *,
               next_command: str | None = None) -> Outcome:
        """BLOCKED for a gate-invalidating reason: the PR is closed with that reason."""
        self.ctx.gh.pr_close(c.slug, number, f"guard-fleet: {reason}")
        return self._outcome(c, "BLOCKED", step, reason, next_command=next_command)

    def _poll(self, cap_s: float, probe: Callable[[], T | None]) -> T | None:
        """Call probe() with backoff 2 -> 30 s until it returns non-None or cap_s (monotonic) has passed."""
        clock, delay = self.ctx.deps.clock, POLL_START
        deadline = clock.monotonic() + cap_s
        while True:
            got = probe()
            if got is not None:
                return got
            now = clock.monotonic()
            if now >= deadline:
                return None
            self.ctx.deps.sleep(min(delay, deadline - now))
            delay = min(delay * 2, POLL_CEILING)

    # -- publish ---------------------------------------------------------------

    def publish(self, consumer: Consumer, rolled: Rolled) -> tuple[int, str, float] | Outcome:
        ctx, c, b, h = self.ctx, consumer, self.branch, rolled.head
        assert h is not None and rolled.worktree is not None
        remote = self._remote_ref(c, f"refs/heads/{b}")
        pushed_at = ctx.deps.clock.monotonic()
        if remote != h:
            if remote is None:
                lease = f"--force-with-lease=refs/heads/{b}:"
            elif f"{REBUILD_FLAG}{c.short}" in self.approval.flags and self.rebuild_remote_ok(c, remote):
                lease = f"--force-with-lease=refs/heads/{b}:{remote}"
            elif f"{REBUILD_FLAG}{c.short}" in self.approval.flags:
                return self._outcome(c, "BLOCKED", "publish",
                                     f"publish: remote {b} is at {remote[:12]}, neither a recorded head nor only "
                                     f"the fleet's bump: inspect {c.slug} {b} by hand; --rebuild will not replace it")
            else:
                return self._outcome(c, "BLOCKED", "publish",
                                     f"publish: remote {b} is at {remote[:12]}, not the gated head {h[:12]}",
                                     next_command=f"guard-fleet land {self.tag} --rebuild {c.short}")
            res = ctx.git(rolled.worktree, "push", lease, "origin", f"{h}:refs/heads/{b}", check=False,
                          env=ctx.child_env)
            if res.rc != 0:
                ctx.deps.err.write(f"{c.short}: push refused:\n{res.stderr.decode('utf-8', errors='replace')}")
                return self._outcome(c, "BLOCKED", "publish", "push: pre-push hook refused")
            pushed_at = ctx.deps.clock.monotonic()

        prs = ctx.gh.pr_list(c.slug, head=b, base=c.default_branch)
        if not prs:
            spec = self._base_lock(c, rolled)
            if spec is None:
                return self._outcome(c, "BLOCKED", "publish", "publish: guard.lock at BASE is unreadable")
            url = self._create_pr(c, rolled, spec)
            number = int(url.rstrip("/").rsplit("/", 1)[1])
        elif len(prs) == 1 and self._ours(prs[0]) and prs[0].get("headRefOid") == h:
            number, url = int(prs[0]["number"]), str(prs[0]["url"])
        else:
            listed = ", ".join(f"#{p.get('number')}" for p in prs)
            return self._outcome(c, "BLOCKED", "publish", f"publish: another open PR on {b}: {listed}")
        self._record(c, "publish", attempt=rolled.attempt, base=rolled.base, head=h, detail={"pr": url})
        self._close_superseded(c, number, url)
        return number, url, pushed_at

    def _ours(self, pr: Mapping) -> bool:
        author = pr.get("author") or {}
        return pr.get("isCrossRepository") is False and isinstance(author, Mapping) and \
            author.get("login") == self.login

    def _create_pr(self, c: Consumer, rolled: Rolled, spec: LockSpec) -> str:
        body = prbody.render(c, version=self.version, p=spec.sha, t=self.t, rolled=rolled,
                             evidence=self.evidence.get(c.short, ()), deploy_line=self.deploy_lines.get(c.short),
                             running_tag=self.running_tag, running_sha=self.running_sha)
        cdir = self.ctx.deps.dirs.consumer_dir(self.tag, c.short)
        cdir.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = cdir / "pr-body.md"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(body)
        return self.ctx.gh.pr_create(c.slug, head=self.branch, base=c.default_branch,
                                     title=f"chore(guard): bump agent-ratchet to v{self.version}", body_file=path)

    def _close_superseded(self, c: Consumer, number: int, url: str) -> None:
        mine = tuple(int(n) for n in self.version.split("."))
        for pr in self.ctx.gh.pr_list_open(c.slug, base=c.default_branch):
            old = parse_fleet_branch(str(pr.get("headRefName") or ""))
            if old is None or not self._ours(pr) or int(pr["number"]) == number:
                continue
            if tuple(int(n) for n in old.split(".")) < mine:
                self.ctx.gh.pr_close(c.slug, int(pr["number"]), f"superseded by {url}")

    # -- before the merge --------------------------------------------------------

    def premerge(self, consumer: Consumer, rolled: Rolled, number: int) -> Outcome | None:
        ctx, c, h, base = self.ctx, consumer, rolled.head, rolled.base
        assert h is not None and base is not None and rolled.worktree is not None
        w = rolled.worktree
        self._waited = False

        def blocked(reason: str, **kw) -> Outcome:
            return self._outcome(c, "BLOCKED", "premerge", f"premerge: {reason}", **kw)

        def invalid(reason: str) -> Outcome:
            return self._close(c, number, "premerge", f"premerge: {reason}")

        pr = ctx.gh.pr_view(c.slug, number, ["state", "baseRefName", "isCrossRepository", "author", "headRefOid"])
        if pr.get("state") != "OPEN":
            return blocked(f"PR #{number} is {pr.get('state')}, not OPEN")
        if pr.get("baseRefName") != c.default_branch:
            return blocked(f"PR #{number} targets {pr.get('baseRefName')!r}, not {c.default_branch!r}",
                           keep_pr_open=True)
        if not self._ours(pr):
            return blocked(f"PR #{number} is not a same-repo PR by {self.login}", keep_pr_open=True)

        if pr.get("headRefOid") != h:
            return invalid(f"head mismatch: the PR head is {str(pr.get('headRefOid'))[:12]}, H is {h[:12]}")
        records, bad = ctx.ledger.records()
        attempt, why = gated_attempt(records, bad, c.short, h)
        if attempt is None:
            return invalid(f"head mismatch: the ledger has no gated attempt on H ({why})")
        local = rev_parse(ctx.git, w, f"refs/heads/{self.branch}")
        if local != h:
            return invalid(f"head mismatch: local {self.branch} is {str(local)[:12]}, H is {h[:12]}")

        spec = self._base_lock(c, rolled)
        if spec is None:
            return invalid("guard.lock at BASE is unreadable")
        want = render_lock(self.t, spec.extras)
        if ctx.gh.contents_raw(c.slug, "guard.lock", h) != want:
            return invalid(f"guard.lock at H on GitHub is not {want!r}")
        g8 = shape.check(ctx.git, w, ctx.mirror, c, base=base, head=h, p=spec.sha, t=self.t, extras=spec.extras)
        if g8.verdict != "PASS":
            return invalid(f"shape: {g8.reason}")
        try:
            peel = validate_target(ctx.git, ctx.mirror, self.tag).sha
        except TargetError as exc:
            return blocked(f"target: {exc}", keep_pr_open=True)
        if peel != self.approval.t:
            return blocked(f"target: {self.tag} now peels to {peel[:12]}, the approval says {self.approval.t[:12]}",
                           keep_pr_open=True)
        if not ctx.gh.merge_commit_allowed(c.slug):
            return blocked(f"merge commits are not allowed on {c.slug}", keep_pr_open=True)

        def mergeability() -> dict | None:
            view = ctx.gh.pr_view(c.slug, number, ["headRefOid", "mergeable", "mergeStateStatus",
                                                   "statusCheckRollup"])
            if view.get("headRefOid") != h or "UNKNOWN" in (view.get("mergeable"), view.get("mergeStateStatus")):
                return None
            return view

        view = self._poll(c.ci_wait_min * 60, mergeability)
        if view is None:
            return blocked(f"mergeability still unknown after {c.ci_wait_min} min", keep_pr_open=True,
                           next_command=self._resume())
        if view.get("mergeable") != "MERGEABLE" or view.get("mergeStateStatus") not in MERGE_STATES_OK:
            return blocked(f"PR #{number} is {view.get('mergeable')} / {view.get('mergeStateStatus')}",
                           keep_pr_open=True, next_command=self._resume())

        moved = self._base_moved(c, rolled, spec, w)
        if moved is not None:
            return self._close(c, number, "premerge", f"premerge: {moved}",
                               next_command=f"guard-fleet land {self.tag} --rebuild {c.short}")

        out, self._waited = self._quiet(c)
        return out

    def _gate_hits(self, c: Consumer, repo: Path, spec: LockSpec, base: str, d: str) -> list[str]:
        ctx = self.ctx
        diff = [p for p in ctx.git(repo, "diff", "--name-only", "-z", "--no-renames", base, d).stdout.decode(
            "utf-8", errors="surrogateescape").split("\0") if p]
        if not diff:
            return []
        inputs = gate_inputs(ctx.deps.run, ctx.child_env, ctx.git, repo, c, base=base, d=d, p=spec.sha, t=self.t,
                             extras=spec.extras, g7_files=api_compat.read_files(ctx.git, repo, base))
        return touches(diff, inputs)

    def _base_moved(self, c: Consumer, rolled: Rolled, spec: LockSpec, w: Path) -> str | None:
        """None when the default branch did not move in a way that invalidates the gates; else why."""
        base = rolled.base
        assert base is not None
        ref = f"refs/heads/{c.default_branch}"
        d2 = self._remote_ref(c, ref)
        if d2 == base:
            return None
        if d2 is None:
            return f"base moved: origin has no {c.default_branch}"
        fetch_default(self.ctx.git, c.dir, c.default_branch)
        if not is_ancestor(self.ctx.git, c.dir, base, d2):
            return f"base moved: BASE {base[:12]} is not an ancestor of {c.default_branch} {d2[:12]}"
        try:
            hits = self._gate_hits(c, w, spec, base, d2)
        except AskError as exc:
            return f"base moved: cannot tell the gate inputs ({exc})"
        except GitNetworkError:
            raise
        except GitError as exc:
            return f"base moved: cannot diff BASE..{c.default_branch} ({exc})"
        if hits:
            return f"base moved: {c.default_branch} {d2[:12]} changed gate inputs: {', '.join(hits)}"
        return None

    def _quiet(self, c: Consumer) -> tuple[Outcome | None, bool]:
        """(BLOCKED or None, waited): waited is True when any poll saw a run in flight."""
        if not c.quiet_before_merge:
            return None, False

        def busy() -> list[str]:
            out = []
            for wf in c.quiet_before_merge:
                runs = self.ctx.gh.run_list(c.slug, workflow=wf, branch=c.default_branch)
                out += [f"{wf} #{r.get('databaseId')} {r.get('status')}" for r in runs
                        if str(r.get("status") or "").lower() != "completed"]
            return out

        last: list[str] = []
        waited = False

        def probe() -> bool | None:   # True once no listed workflow has a run in flight
            nonlocal last, waited
            last = busy()
            waited = waited or bool(last)
            return True if not last else None

        now = self.ctx.deps.clock.monotonic()
        if self._quiet_deadline is None:
            self._quiet_deadline = now + c.ci_wait_min * 60
        if self._poll(max(0.0, self._quiet_deadline - now), probe) is None:
            return self._outcome(c, "BLOCKED", "premerge", f"premerge: deploy queue busy: {', '.join(last)}",
                                 keep_pr_open=True, next_command=self._resume()), True
        return None, waited

    # -- merge and verify ------------------------------------------------------

    def merge(self, consumer: Consumer, rolled: Rolled, number: int) -> Outcome:
        ctx, c, h = self.ctx, consumer, rolled.head
        assert h is not None
        res = ctx.gh.pr_merge(c.slug, number, h)
        view: dict = {}
        for delay in (*MERGE_READBACK, None):   # whatever the exit code, read the result back
            view = ctx.gh.pr_view(c.slug, number, ["state", "mergeCommit", "headRefOid"])
            if view.get("state") != "OPEN" or delay is None:
                break
            ctx.deps.sleep(delay)
        state = view.get("state")
        if state == "OPEN":
            tail = res.stderr.decode("utf-8", errors="replace").strip()
            return self._outcome(c, "BLOCKED", "merge", f"merge: PR #{number} is still OPEN (gh rc {res.rc}: "
                                 f"{tail or 'no output'})", keep_pr_open=True, next_command=self._resume())
        if state != "MERGED":
            return self._outcome(c, "BLOCKED", "merge", f"merge: PR #{number} is {state}")
        merge_sha = str((view.get("mergeCommit") or {}).get("oid") or "")
        fetch_default(ctx.git, c.dir, c.default_branch)
        second = rev_parse(ctx.git, c.dir, f"{merge_sha}^2") if merge_sha else None
        if view.get("headRefOid") != h or second != h:
            reason = (f"merge: PR #{number} merged at head {str(view.get('headRefOid'))[:12]} "
                      f"(merge {merge_sha[:12]}, second parent {str(second)[:12]}), not H {h[:12]}")
            self._record(c, "merge", attempt=rolled.attempt, base=rolled.base, head=h,
                         detail={"verdict": "fail", "merge": merge_sha, "reason": reason})
            return self._outcome(c, "FAILED", "merge", reason, merge_sha=merge_sha or None)
        self._record(c, "merge", attempt=rolled.attempt, base=rolled.base, head=h,
                     detail={"verdict": "pass", "merge": merge_sha})
        return self.verify(consumer, rolled, merge_sha)

    def verify(self, consumer: Consumer, rolled: Rolled, merge_sha: str) -> Outcome:
        ctx, c, h, base = self.ctx, consumer, rolled.head, rolled.base
        assert h is not None and base is not None
        misses: list[str] = []
        try:
            d = self._remote_ref(c, f"refs/heads/{c.default_branch}")   # D first, then its objects
            fetch_default(ctx.git, c.dir, c.default_branch)
            spec = self._base_lock(c, rolled)
            if spec is None:
                raise _Miss("guard.lock at BASE is unreadable")
            if d is None:
                misses.append(f"origin has no {c.default_branch}")
            else:
                if not is_ancestor(ctx.git, c.dir, h, d):
                    misses.append(f"H {h[:12]} is not an ancestor of {c.default_branch} {d[:12]}")
                want = render_lock(self.t, spec.extras)
                if show_bytes(ctx.git, c.dir, d, "guard.lock") != want:
                    misses.append(f"guard.lock at {c.default_branch} is not {want!r}")
                shim = show_bytes(ctx.git, ctx.mirror, self.t, "consumer/guard")
                if shim is None or show_bytes(ctx.git, c.dir, d, "scripts/guard") != shim:
                    misses.append(f"scripts/guard at {c.default_branch} is not {self.tag}:consumer/guard")
            first = rev_parse(ctx.git, c.dir, f"{merge_sha}^1")
            if first is None:
                misses.append(f"merge commit {merge_sha[:12]} has no first parent here")
            else:
                w = rolled.worktree if rolled.worktree is not None and rolled.worktree.is_dir() else c.dir
                hits = self._gate_hits(c, w, spec, base, first)
                if hits:
                    misses.append(f"the base moved into gate inputs before the merge: {', '.join(hits)}")
        except GitNetworkError:
            raise   # not a verdict: nothing is recorded, the caller maps the network loss
        except (GitError, AskError, _Miss) as exc:
            misses.append(str(exc))
        verdict = "fail" if misses else "pass"
        self._record(c, "verify", attempt=rolled.attempt, base=base, head=h,
                     detail={"verdict": verdict, "merge": merge_sha, **({"reason": "; ".join(misses)} if misses
                                                                         else {})})
        if misses:
            return self._outcome(c, "FAILED", "verify", "verify: " + "; ".join(misses), merge_sha=merge_sha)
        return self._outcome(c, "LANDED", "verify", "", merge_sha=merge_sha)

    def push_run_gate(self, consumer: Consumer, merge_sha: str) -> Outcome | None:
        ctx, c = self.ctx, consumer
        found: dict[str, object] = {}

        def probe() -> bool | None:
            jobs = []
            for run in ctx.gh.run_list(c.slug, commit=merge_sha, event="push"):
                jobs += ctx.gh.run_jobs(c.slug, int(run["databaseId"]))
            gov = [j for j in jobs if j.get("name") == GOVERNANCE_JOB]
            found["jobs"], found["gov"] = jobs, gov
            if gov and all(str(j.get("status") or "").lower() == "completed" for j in gov):
                return True
            return None

        done = self._poll(c.ci_wait_min * 60, probe)
        jobs = found.get("jobs") or []
        gov = found.get("gov") or []
        assert isinstance(jobs, list) and isinstance(gov, list)
        for j in jobs:
            if j.get("name") != GOVERNANCE_JOB and str(j.get("conclusion") or "").lower() not in (
                    "success", "neutral", "skipped", ""):
                ctx.deps.out.write(f"{c.short}: push run: job {j.get('name')!r} concluded {j.get('conclusion')} "
                                   f"(reported only)\n")
        if done is None:
            reason = (f"push-run: no completed {GOVERNANCE_JOB!r} job for {merge_sha[:12]} within "
                      f"{c.ci_wait_min} min")
        else:
            bad = [str(j.get("conclusion")) for j in gov if str(j.get("conclusion") or "").lower() != "success"]
            reason = f"push-run: {GOVERNANCE_JOB!r} concluded {', '.join(bad)}" if bad else ""
        h = rev_parse(ctx.git, c.dir, f"{merge_sha}^2")
        records, bad = ctx.ledger.records()
        attempt = gated_attempt(records, bad, c.short, h)[0] if h else None
        self._record(c, "push-run", attempt=attempt, base=None, head=h,
                     detail={"verdict": "fail" if reason else "pass", "merge": merge_sha,
                             **({"reason": reason} if reason else {})})
        if reason:
            return self._outcome(c, "FAILED", "push-run", reason, merge_sha=merge_sha)
        return None

    def deploy_report(self, consumer: Consumer, merge_sha: str) -> list[str]:
        lines = []
        for wf in consumer.deploy_workflows:
            try:
                state = self.ctx.gh.workflow_state(consumer.slug, wf)
            except GhNotFound:
                state = "not found"
            runs = self.ctx.gh.run_list(consumer.slug, commit=merge_sha, workflow=wf)
            shown = ", ".join(f"#{r.get('databaseId')} {r.get('event')} {r.get('status')}"
                              + (f"/{r.get('conclusion')}" if r.get("conclusion") else "") for r in runs)
            lines.append(f"{consumer.short}: deploy {wf}: {state}; runs for {merge_sha[:12]}: {shown or 'none'}")
        return lines

    # -- the whole consumer ----------------------------------------------------

    def _finish(self, c: Consumer, out: Outcome) -> Outcome:
        assert out.merge_sha is not None
        for line in self.deploy_report(c, out.merge_sha):
            self.ctx.deps.out.write(line + "\n")
        ctx = self.ctx
        done = cleanup_landed(CleanupContext(ctx.deps, ctx.git, ctx.gh, ctx.mirror, ctx.cfg), c, self.version)
        return dataclasses.replace(out, cleanup=tuple(line for _, line in done),
                                   cleanup_kept=any(not removed for removed, _ in done))

    def land_consumer(self, consumer: Consumer, rolled: Rolled) -> Outcome:
        c = consumer
        if rolled.state != "GATED" or rolled.head is None:
            return self._outcome(c, "BLOCKED", "approval", f"not gated: {rolled.step}: {rolled.reason}")
        if not self.approval.covers(c.short, rolled.head, self.t):
            return self._outcome(c, "BLOCKED", "approval", "not in approval")
        pub = self.publish(c, rolled)
        if isinstance(pub, Outcome):
            return pub
        number, url, pushed_at = pub
        verdict, checks = wait_for_ci(self.ctx.deps, self.ctx.gh, c.slug, number, rolled.head, mode=c.ci,
                                      cap_min=c.ci_wait_min, pushed_at_mono=pushed_at)
        self._record(c, "ci", attempt=rolled.attempt, base=rolled.base, head=rolled.head, detail={"verdict": verdict})
        if verdict == "timeout":
            return self._outcome(c, "BLOCKED", "ci", f"ci: still pending after {c.ci_wait_min} min", pr_url=url,
                                 keep_pr_open=True, next_command=self._resume())
        if verdict != "pass":   # "blocks" and anything unexpected fail closed
            failing = ", ".join(f"{k.name} ({k.detail})" for k in checks if k.verdict == "blocks") or "no checks"
            return self._outcome(c, "BLOCKED", "ci", f"ci: {verdict}: blocking checks: {failing}", pr_url=url,
                                 keep_pr_open=True, next_command=self._resume())
        self._quiet_deadline = None
        out = self.premerge(c, rolled, number)
        reruns = 0
        # a quiet wait or a sleep since the previous check: re-check head, base and tag before merging
        while out is None and (self._drifted() | self._waited):
            if reruns == PREMERGE_RERUNS:
                out = self._outcome(c, "BLOCKED", "premerge", f"premerge: still re-checking after {reruns} "
                                    "re-runs (deploy queue or clock kept moving)", keep_pr_open=True,
                                    next_command=self._resume())
                break
            reruns += 1
            out = self.premerge(c, rolled, number)
        if out is None:
            out = self.merge(c, rolled, number)
        out = dataclasses.replace(out, pr_url=url)
        return self._finish(c, out) if out.state == "LANDED" else out

    def merged_verified(self, consumer: Consumer) -> Outcome:
        """The fleet PR MERGED at a gated H, verified live (no push-run gate).

        It writes the ledger "verify" record and does an object-only fetch of the default branch; it never pushes,
        closes, merges or cleans up.

        LANDED, FAILED (the merge or the verify misses) or BLOCKED (no merged fleet PR at a gated head).
        """
        ctx, c = self.ctx, consumer
        records, bad = ctx.ledger.records()
        for pr in ctx.gh.pr_list(c.slug, head=self.branch, base=c.default_branch, state="merged"):
            if not self._ours(pr):
                continue
            h = str(pr.get("headRefOid") or "")
            attempt, _ = gated_attempt(records, bad, c.short, h)
            if attempt is None:
                continue
            view = ctx.gh.pr_view(c.slug, int(pr["number"]), ["state", "mergeCommit", "headRefOid"])
            merge_sha = str((view.get("mergeCommit") or {}).get("oid") or "")
            if view.get("state") != "MERGED" or view.get("headRefOid") != h or not merge_sha:
                continue
            fetch_default(ctx.git, c.dir, c.default_branch)
            if rev_parse(ctx.git, c.dir, f"{merge_sha}^2") != h:
                return self._outcome(c, "FAILED", "verify", f"verify: merge {merge_sha[:12]} does not merge H "
                                     f"{h[:12]}", pr_url=str(pr.get("url")), merge_sha=merge_sha)
            # BASE as the gates saw it (a resumed roll gates on the merge-base, not on the plan's D)
            base = next((r.base for r in reversed(records) if r.attempt == attempt and r.step == "G8"), None)
            rolled = Rolled(c.short, "GATED", "gates", "", base, h, attempt, "", {}, None, None)
            return dataclasses.replace(self.verify(c, rolled, merge_sha), pr_url=str(pr.get("url")))
        return self._outcome(c, "BLOCKED", "verify", f"verify: no merged fleet PR on {self.branch} at a gated head")

    def reverify_current(self, consumer: Consumer, *, canary: bool) -> Outcome:
        """A consumer CURRENT at T with a ledger attempt for T: its fleet PR merged at a gated H, re-verified live."""
        out = self.merged_verified(consumer)
        if out.state == "LANDED" and canary:
            assert out.merge_sha is not None
            gate = self.push_run_gate(consumer, out.merge_sha)
            if gate is not None:
                out = dataclasses.replace(gate, pr_url=out.pr_url)
        return self._finish(consumer, out) if out.state == "LANDED" else out

    # -- --rebuild -------------------------------------------------------------

    def _g8_from_merge_base(self, c: Consumer, tip: str) -> tuple[str, list[str]] | str:
        """(merge-base, commit list) when merge-base(tip, D)..tip is strictly the fleet's bump; else why not."""
        ctx = self.ctx
        d = self._remote_ref(c, f"refs/heads/{c.default_branch}")
        if d is None:
            return f"origin has no {c.default_branch}"
        fetch_default(ctx.git, c.dir, c.default_branch)
        mb = ctx.git(c.dir, "merge-base", tip, d, check=False)
        if mb.rc != 0 or not mb.text.strip():
            return f"{tip[:12]} shares no history with {c.default_branch}"
        base = mb.text.strip()
        spec = self._lock_at(c.dir, base)
        if spec is None:
            return f"guard.lock at the merge-base {base[:12]} is missing or malformed"
        g8 = shape.check(ctx.git, c.dir, ctx.mirror, c, base=base, head=tip, p=spec.sha, t=self.t,
                         extras=spec.extras)
        if g8.verdict != "PASS":
            return g8.reason
        commits = ctx.git(c.dir, "log", "--reverse", "--format=%H %s", f"{base}..{tip}").text.splitlines()
        return base, commits

    def rebuild_remote_commits(self, consumer: Consumer, remote_head: str) -> list[str] | None:
        """What a --rebuild push would replace on the remote B, as "<sha> <subject>" lines (oldest first).

        [] for a head the ledger recorded; None when remote_head is not strictly the fleet's bump (no replace).
        """
        if remote_head in self.ctx.ledger.heads_recorded(consumer.short):
            return []
        self.ctx.git.retrying(consumer.dir, "fetch", "--no-tags", "--no-write-fetch-head", "--refmap=", "origin",
                              f"refs/heads/{self.branch}")   # objects only: the main checkout's refs stay
        if self.ctx.git(consumer.dir, "cat-file", "-e", f"{remote_head}^{{commit}}", check=False).rc != 0:
            return None
        g8 = self._g8_from_merge_base(consumer, remote_head)
        return None if isinstance(g8, str) else g8[1]

    def rebuild_remote_ok(self, consumer: Consumer, remote_head: str) -> bool:
        """May a push force over the live remote B? Only over a head the ledger recorded, or a strict-G8 bump."""
        return self.rebuild_remote_commits(consumer, remote_head) is not None

    def rebuild_local(self, consumer: Consumer) -> None:
        """Reset the local B and W before a fresh roll; raises RebuildBlocked unless they are only the fleet's."""
        ctx, c, b = self.ctx, consumer, self.branch
        tip = rev_parse(ctx.git, c.dir, f"refs/heads/{b}")
        if tip is None:
            return
        g8 = self._g8_from_merge_base(c, tip)
        if isinstance(g8, str):
            raise RebuildBlocked(f"rebuild: {b} is not only the fleet's bump: {g8}")
        w = worktree_for(ctx.cfg, c, self.version)
        if w.exists():
            link = fleet_node_modules(c, w)
            fleet = set(_FLEET_PATHS) | ({c.pin_file} if c.pin_kind != "none" and c.pin_file else set()) | (
                {"uv.lock"} if c.pin_kind == "pyproject" else set())
            restore: list[str] = []
            for entry in status_porcelain(ctx.git, w, ignored=True):   # 1. prove every entry, mutate nothing
                path = entry[3:]
                if link and path.rstrip("/") == "node_modules":
                    continue
                if entry[:2] == "!!":
                    if not ignored_allowed(path):   # worktree remove would delete it silently
                        raise RebuildBlocked(f"rebuild: {w} has an ignored path outside the allowlist: {path}")
                    continue
                try:
                    same = path in fleet and (w / path).read_bytes() == show_bytes(ctx.git, w, b, path)
                except OSError:
                    same = False
                if not same:
                    raise RebuildBlocked(f"rebuild: {w} has a change the fleet did not write: {entry}")
                restore.append(path)
            if link:   # 2. only now: unlink, restore, remove
                (w / "node_modules").unlink()
            for path in restore:
                ctx.git(w, "restore", "--staged", "--worktree", "--source", b, "--", path)
            removed = ctx.git(c.dir, "worktree", "remove", str(w), check=False)
            if removed.rc != 0:
                raise RebuildBlocked(f"rebuild: worktree remove {w} refused: "
                                     f"{removed.stderr.decode('utf-8', errors='replace').strip()}")
        ctx.git(c.dir, "branch", "-D", b)
