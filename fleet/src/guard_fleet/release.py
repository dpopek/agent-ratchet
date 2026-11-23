"""`release` and `land`: plan, roll, one confirmation, then land the rings (spec 6.8, 6.11, 6.12)."""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from typing import Sequence

from . import venvs
from .cleanup import CleanupContext, Item, cleanup_landed, collect
from .config import Consumer, FleetConfig
from .confirm import ask, reason_text
from .deps import Deps
from .difftool import run_diff
from .env import agent_markers_present, refusal_lines
from .exits import Cancelled, FleetExit, NoHelper, UsageError, combine
from .gh import Gh, GhAuthError, GhNetworkError
from .git import Git, GitNetworkError, ls_remote, rev_parse
from .land import REBUILD_FLAG, Approval, Lander, Outcome, RebuildBlocked
from .ledger import Ledger
from .locks import RunLock, guard_bump_running
from .mirror import refresh_mirror
from .names import branch_for, parse_fleet_branch, worktree_for
from .plan import Planner, _clients
from .report import EndState, render_end
from .rings import ConsumerState, billing_state, deploy_lines, land_rings, rebuild_state, render_confirmation
from .roll import RollContext, prepare
from .selfcheck import self_check
from .target import Target, check_tag_syntax, validate_target

NETWORK_ERRORS = (GhAuthError, GhNetworkError, GitNetworkError)


@dataclass(frozen=True)
class Options:
    tag: str
    only: tuple[str, ...]
    include_unexposed: bool
    rebuild: tuple[str, ...]
    diff: bool
    hold_ring_2: bool
    rings: tuple[int, ...]


def resume_command(tag: str) -> str:
    return f"guard-fleet land {tag}"


def network_kind(exc: BaseException) -> str:
    return "gh auth" if isinstance(exc, GhAuthError) else "network lost"


class _Run:
    """One `release` or `land` run, under the exclusive run lock."""

    def __init__(self, deps: Deps, cfg: FleetConfig, opts: Options, *, command: str, lock_update: bool,
                 running_sha: str) -> None:
        self.deps, self.cfg, self.opts, self.command = deps, cfg, opts, command
        self.lock_update, self.running_sha = lock_update, running_sha
        self.markers = agent_markers_present(deps.environ)
        self.git: Git
        self.gh: Gh
        self.ctx: RollContext
        self.target: Target
        self.running_tag = ""
        self.login = ""
        self.version = ""
        self.branch = ""
        self.states: dict[str, ConsumerState] = {}   # every consumer of this run (not left out by --only)
        self.rings: tuple[int, ...] = (1, 2)
        self.deferred: list[str] = []            # re-verified LANDED: cleanup waits for this run's confirmation
        self.pending: dict[str, list[Item]] = {}  # deferred cleanup never run: listed in the end table
        self.unconfirmed = False                 # stopped at the confirmation (no helper, cancelled, timeout)

    # -- setup -----------------------------------------------------------------

    def start(self) -> None:
        deps, opts = self.deps, self.opts
        self.ctx = RollContext(deps, self.git, self.gh, refresh_mirror(deps, self.git), self.cfg,
                               Target("", "", (0, 0, 0)), Ledger(deps.dirs.ledger(opts.tag), deps.clock),
                               self.lock_update, self.git.env)
        self.target = validate_target(self.git, self.ctx.mirror, opts.tag)
        self.running_tag = self_check(self.git, self.ctx.mirror, self.running_sha, target_sha=self.target.sha)
        self.ctx.target = self.target
        self.version = ".".join(str(n) for n in self.target.version)
        self.branch = branch_for(self.version)
        self.login = self.gh.user_login()

    def lander(self, approval: Approval | None = None, *, deploy: dict[str, str] | None = None) -> Lander:
        approval = approval or Approval(self.target.tag, self.target.sha, {}, frozenset())
        return Lander(self.ctx, approval, self.login, running_tag=self.running_tag, running_sha=self.running_sha,
                      evidence={s.short: s.plan.evidence for s in self.states.values()}, deploy_lines=deploy)

    # -- plan ------------------------------------------------------------------

    def plan(self) -> bool:
        """Plan every consumer of the run; False when gh or the network stopped a row (the run ends, exit 4)."""
        planner = Planner(self.deps, self.git, self.gh, self.ctx.mirror, lock_free=False)
        for c in self.cfg.consumers:
            if self.opts.only and c.short not in self.opts.only:
                continue
            row = planner.plan_consumer(c, self.target, include_unexposed=self.opts.include_unexposed)
            self.states[c.short] = ConsumerState(c.short, c.ring, row, None, None)
        for short in self.opts.rebuild:
            s = self.states.get(short)
            if s is None:
                raise UsageError(f"--rebuild {short}: the consumer is not part of this run (--only)")
            if s.plan.decision != "BUMP" and not self.has_fleet_branch(self.cfg.by_short(short)):
                raise UsageError(f"--rebuild {short}: it is {s.plan.decision} and has no fleet branch {self.branch}")
        return not planner.gh_stopped

    def has_fleet_branch(self, c: Consumer) -> bool:
        if rev_parse(self.git, c.dir, f"refs/heads/{self.branch}") is not None:
            return True
        return self.remote_head(c) is not None

    def has_leftover(self, c: Consumer) -> bool:
        return (rev_parse(self.git, c.dir, f"refs/heads/{self.branch}") is not None
                or worktree_for(self.cfg, c, self.version).exists())

    def remote_head(self, c: Consumer) -> str | None:
        ref = f"refs/heads/{self.branch}"
        return ls_remote(self.git, c.dir, f"https://github.com/{c.slug}", ref).get(ref)

    def put(self, short: str, **changes: object) -> None:
        self.states[short] = dataclasses.replace(self.states[short], **changes)   # type: ignore[arg-type]

    # -- resume: CURRENT consumers --------------------------------------------------

    def reverify(self) -> bool:
        """Re-verify CURRENT consumers the fleet rolled for this tag; False when one FAILED (the run stops)."""
        records, _ = self.ctx.ledger.records()
        attempted = {r.consumer for r in records if r.step == "attempt-start"}
        canaries = {c.short for c in self.cfg.canaries(1)}
        lander = self.lander()
        for c in self.cfg.consumers:
            s = self.states.get(c.short)
            if s is None or s.plan.decision != "CURRENT":
                continue
            if c.short in attempted:
                self.put(c.short, outcome=self.reverify_one(lander, c, canary=c.short in canaries))
            else:   # current without a fleet roll for this tag: nothing to verify, nothing to land
                self.put(c.short, outcome=Outcome(c.short, "LANDED", "current", s.plan.reason, None, None, None,
                                                  False))
        return not any(s.outcome is not None and s.outcome.state == "FAILED" for s in self.states.values())

    def reverify_one(self, lander: Lander, c: Consumer, *, canary: bool) -> Outcome:
        """Lander.reverify_current without its cleanup: that waits for this run's confirmation (R22.5)."""
        out = lander.merged_verified(c)
        if out.state == "LANDED" and canary:
            assert out.merge_sha is not None
            gate = lander.push_run_gate(c, out.merge_sha)
            if gate is not None:
                out = dataclasses.replace(gate, pr_url=out.pr_url)
        if out.state == "LANDED":
            assert out.merge_sha is not None
            for line in lander.deploy_report(c, out.merge_sha):
                self.deps.out.write(line + "\n")
            self.deferred.append(c.short)
        return out

    def cleanup_ctx(self) -> CleanupContext:
        return CleanupContext(self.deps, self.git, self.gh, self.ctx.mirror, self.cfg)

    def clean_deferred(self) -> None:
        """After this run's confirmation: clean up the re-verified consumers, under that approval."""
        for short in self.deferred:
            done = cleanup_landed(self.cleanup_ctx(), self.cfg.by_short(short), self.version)
            out = self.states[short].outcome
            assert out is not None
            self.put(short, outcome=dataclasses.replace(out, cleanup=tuple(line for _, line in done),
                                                        cleanup_kept=any(not removed for removed, _ in done)))
        self.deferred = []

    def list_deferred(self) -> None:
        """No confirmation in this run: nothing is removed, the leftovers are listed (read only)."""
        for short in self.deferred:
            items = collect(self.cleanup_ctx(), self.cfg.by_short(short), version=self.version, remote=True)
            if items:
                self.pending[short] = items
        self.deferred = []

    # -- roll ------------------------------------------------------------------

    def in_rings(self, c: Consumer) -> bool:
        return c.ring in self.rings

    def roll(self, *, roll_new: bool) -> list[str]:
        """--rebuild resets, then roll (release) or re-gate leftovers (land); returns the --diff lines."""
        lander = self.lander()
        for short in self.opts.rebuild:
            c, s = self.cfg.by_short(short), self.states[short]
            if s.plan.decision == "BUMP":
                self.states[short] = rebuild_state(lander, c, s)
                continue
            try:
                lander.rebuild_local(c)
            except RebuildBlocked as exc:
                self.put(short, outcome=Outcome(short, "BLOCKED", "rebuild", str(exc), None, None, None, False))
        for c in self.cfg.consumers:
            s = self.states.get(c.short)
            if s is None or s.plan.decision != "BUMP" or s.rolled is not None or s.outcome is not None:
                continue
            if self.in_rings(c) and (roll_new or self.has_leftover(c)):
                self.put(c.short, rolled=prepare(self.ctx, c, s.plan))
        lines = []
        if self.opts.diff:
            for s in self.gated():
                assert s.rolled is not None and s.rolled.base and s.rolled.worktree and s.plan.p
                c = self.cfg.by_short(s.short)
                lines.append(f"{s.short}: " + run_diff(self.ctx, c, base=s.rolled.base, p=s.plan.p,
                                                       t=self.target.sha, extras=s.plan.extras,
                                                       worktree=s.rolled.worktree))
        return lines

    def gated(self) -> list[ConsumerState]:
        order = [c for ring in self.rings for c in self.cfg.ring_order(ring)]
        found = [self.states.get(c.short) for c in order]
        return [s for s in found if s is not None and s.outcome is None and s.rolled is not None
                and s.rolled.state == "GATED"]

    # -- the confirmation --------------------------------------------------------

    def confirmation(self, diff_lines: Sequence[str]) -> tuple[str, str, dict[str, str]]:
        """(table, reason, per-consumer PR-body deploy line), all from live state."""
        gated = self.gated()
        lander = self.lander()
        rebuild_commits: dict[str, list[str] | None] = {}
        for short in self.opts.rebuild:
            s = self.states[short]
            if s.rolled is None or s.rolled.state != "GATED":
                continue
            remote = self.remote_head(self.cfg.by_short(short))
            if remote is not None and remote != s.rolled.head:
                rebuild_commits[short] = lander.rebuild_remote_commits(self.cfg.by_short(short), remote)
        d_by_short = {s.short: s.plan.d for s in self.states.values() if s.plan.d}
        dl = deploy_lines(self.gh, self.cfg, d_by_short)
        per_short = {}
        for short in self.states:
            mine = [line.removeprefix(f"{short}: ") for line in dl if line.startswith(f"{short}: ")]
            if mine:
                per_short[short] = "Deploy: " + "; ".join(mine)
        title = f"chore(guard): bump agent-ratchet to v{self.version}"
        shown = [s for s in self.states.values() if self.in_rings(self.cfg.by_short(s.short))]
        table = render_confirmation(
            self.target, self.running_sha, shown,
            prs_to_open=[f"{s.short}: {title} ({self.branch})" for s in gated],
            prs_to_close=[line for s in gated for line in self.superseded(self.cfg.by_short(s.short))],
            canary_order=[c.short for c in self.cfg.canaries(1) if c.short in self.states and 1 in self.rings],
            deploy_lines=dl, billing=billing_state(self.gh, self.cfg),
            notes={s.short: self.cfg.by_short(s.short).confirm_note for s in shown
                   if self.cfg.by_short(s.short).confirm_note},
            diff_lines=diff_lines, rebuild_commits=rebuild_commits, cfg=self.cfg)
        by_ring = {ring: [s.short for s in gated if s.ring == ring] for ring in self.rings}
        reason = reason_text(self.command, self.target.tag, self.target.sha, by_ring, markers=self.markers)
        return table, reason, per_short

    def superseded(self, c: Consumer) -> list[str]:
        """Open same-repo fleet PRs by the operator from an older version: land closes them (Lander)."""
        out = []
        for pr in self.gh.pr_list_open(c.slug, base=c.default_branch):
            old = parse_fleet_branch(str(pr.get("headRefName") or ""))
            author = pr.get("author") or {}
            if old is None or pr.get("isCrossRepository") is not False or not isinstance(author, dict) \
                    or author.get("login") != self.login:
                continue
            if tuple(int(n) for n in old.split(".")) < self.target.version:
                out.append(f"{c.short}: #{pr.get('number')} {pr.get('headRefName')}")
        return out

    # -- land and the end ------------------------------------------------------

    def land(self, approval: Approval, deploy: dict[str, str], *, hold_ring_2: bool) -> FleetExit | None:
        """Land the rings; on a lost network: FAILED when this run merged anything, else CANCELLED."""
        lander = self.lander(approval, deploy=deploy)
        before = len(self.ctx.ledger.records()[0])
        try:
            out = land_rings(lander, self.cfg, self.target, list(self.states.values()), rings=self.rings,
                             hold_ring_2=hold_ring_2)
        except NETWORK_ERRORS as exc:
            new = self.ctx.ledger.records()[0][before:]
            merges = {r.consumer: str(r.detail["merge"]) for r in new if r.step == "merge" and r.detail.get("merge")}
            verified = {r.consumer for r in new if r.step == "verify" and r.detail.get("verdict") == "pass"}
            kind = network_kind(exc)
            for short, s in list(self.states.items()):   # the outcomes died with land_rings: rebuild from the ledger
                if s.outcome is not None or s.plan.decision != "BUMP" or not self.in_rings(self.cfg.by_short(short)):
                    continue
                merge = merges.get(short)
                if merge and short in verified:
                    out = Outcome(short, "LANDED", "verify", "", None, merge, None, False)
                else:
                    why = f"{kind}: merged {merge[:12]}, not verified" if merge else f"{kind}: not merged"
                    out = Outcome(short, "NOT_RUN", "land", why, None, merge, resume_command(self.target.tag), False)
                self.put(short, outcome=out)
            self.finish(live=False)   # the network is gone: no venv report
            self.deps.err.write(f"{kind}: {exc}\nResume: {resume_command(self.target.tag)}\n")
            return FleetExit.FAILED if merges else FleetExit.CANCELLED
        self.states = {s.short: s for s in out}
        return None

    def end_state(self, c: Consumer) -> tuple[EndState, FleetExit]:
        tag = self.target.tag
        s = self.states.get(c.short)
        if s is None:
            return EndState(c.short, "NOT RUN", None), FleetExit.OK
        out = s.outcome
        if out is not None:
            if out.state == "LANDED":
                if s.plan.decision == "CURRENT":
                    state = "CURRENT"
                else:
                    state = "LANDED"
                if out.cleanup_kept:
                    return EndState(c.short, f"{state} (cleanup kept: {'; '.join(out.cleanup)})",
                                    "guard-fleet cleanup"), FleetExit.BLOCKED
                items = self.pending.get(c.short)
                if items:   # deferred, not kept: it does not make the run BLOCKED
                    remote = " --remote" if any(i.remote_head for i in items) else ""
                    return (EndState(c.short, f"{state} (cleanup pending: {'; '.join(map(_where, items))})",
                                     f"guard-fleet cleanup {tag}{remote}"), FleetExit.OK)
                return EndState(c.short, state, None), FleetExit.OK
            if out.state == "HELD":
                return EndState(c.short, "HELD", out.next_command), FleetExit.OK
            label = {"NOT_RUN": "NOT RUN"}.get(out.state, out.state)
            code = FleetExit.FAILED if out.state == "FAILED" else FleetExit.BLOCKED
            nxt = out.next_command
            if out.step == "roll" and s.rolled is None:
                nxt = f"guard-fleet release {tag}"   # land rolls nothing new
            return (EndState(c.short, f"{label} {out.step}: {out.reason}", nxt, self.needs_flag(nxt)), code)
        if not self.in_rings(c):
            return EndState(c.short, f"{s.plan.decision} (not in --ring {', '.join(map(str, self.rings))})",
                            f"guard-fleet land {tag} --ring {c.ring}"), FleetExit.OK
        if s.plan.decision == "SKIP":
            return EndState(c.short, "SKIP", None), FleetExit.OK
        if s.plan.decision == "BLOCKED":
            return EndState(c.short, f"BLOCKED plan: {s.plan.reason}", None), FleetExit.BLOCKED
        if s.rolled is None:
            nxt = f"guard-fleet release {tag}"
            return EndState(c.short, "BLOCKED roll: not rolled", nxt, True), FleetExit.BLOCKED
        if s.rolled.state == "BLOCKED":
            nxt = s.rolled.manual_step or f"guard-fleet {self.command} {tag}"
            return (EndState(c.short, f"BLOCKED {s.rolled.step}: {s.rolled.reason}", nxt, self.needs_flag(nxt)),
                    FleetExit.BLOCKED)
        # stopped at the confirmation: the confirmation's own code (4 or 5) speaks for it
        code = FleetExit.OK if self.unconfirmed else FleetExit.BLOCKED
        return EndState(c.short, "GATED, not landed", resume_command(tag)), code

    @staticmethod
    def needs_flag(next_command: str | None) -> bool:
        return bool(next_command) and (next_command.startswith("guard-fleet release ")   # type: ignore[union-attr]
                                       or " --rebuild " in next_command)               # type: ignore[operator]

    def finish(self, extra: Sequence[FleetExit] = (), *, live: bool = True) -> FleetExit:
        if live:
            self.list_deferred()
        ends = [self.end_state(c) for c in self.cfg.consumers]
        drift = live and venvs.drifted(venvs.report(self.deps, self.git, self.gh, self.cfg, only=()))
        self.deps.out.write(render_end([e for e, _ in ends], markers=self.markers, venv_drift=drift))
        return combine([*(code for _, code in ends), *extra])

    def stop_all(self, step: str, reason: str) -> None:
        """Mark every unsettled consumer NOT RUN: the run ends before any further step."""
        for short, s in list(self.states.items()):
            if s.outcome is None and s.plan.decision not in ("SKIP", "BLOCKED"):
                self.put(short, outcome=Outcome(short, "NOT_RUN", step, reason, None, None,
                                                resume_command(self.target.tag), False))


def _where(item: Item) -> str:
    parts = [name for name, there in (("worktree", item.worktree), ("local", item.local_head),
                                      ("remote", item.remote_head)) if there]
    return f"{item.branch} ({', '.join(parts)})"


def _run(deps: Deps, cfg: FleetConfig, opts: Options, *, command: str, lock_update: bool, running_sha: str,
         typed: str, needs_flag: bool, roll_new: bool, rings: tuple[int, ...], hold_ring_2: bool) -> FleetExit:
    check_tag_syntax(opts.tag)   # before any lock or git call
    for short in (*opts.only, *opts.rebuild):
        cfg.by_short(short)
    for short in opts.rebuild:   # before any local mutation: a rebuilt consumer outside the rings never lands
        ring = cfg.by_short(short).ring
        if ring not in rings:
            raise UsageError(f"--rebuild {short}: it is in ring {ring}, not in --ring {', '.join(map(str, rings))}")
    run = _Run(deps, cfg, opts, command=command, lock_update=lock_update, running_sha=running_sha)
    run.rings = rings
    run.git, run.gh = _clients(deps)
    lock = RunLock(deps.dirs.run_lock)
    if not lock.acquire(exclusive=True):
        raise UsageError(f"lock busy: another guard-fleet run holds {deps.dirs.run_lock}")
    try:
        if guard_bump_running(deps.run, run.git.env, deps.dirs.home):
            raise UsageError("guard_bump.sh is running")
        if needs_flag and not lock_update:
            for line in refusal_lines(typed, markers=run.markers):
                deps.out.write(line + "\n")
            return FleetExit.USAGE
        run.start()
        if not run.plan():
            deps.err.write(f"gh or the network stopped the plan\nResume: {resume_command(opts.tag)}\n")
            run.stop_all("plan", "gh or the network stopped the plan")
            return run.finish([FleetExit.CANCELLED])
        if not run.reverify():
            run.stop_all("stopped", "a consumer FAILED its live re-verify")
            return run.finish()
        diff_lines = run.roll(roll_new=roll_new)
        gated = run.gated()
        if not gated:
            return run.finish()
        table, reason, deploy = run.confirmation(diff_lines)
        try:
            ask(deps, table, reason)
        except NoHelper as exc:
            deps.err.write(f"no confirmation helper: {exc}\n")
            run.unconfirmed = True
            return run.finish([FleetExit.NO_HELPER])
        except Cancelled as exc:
            deps.err.write(f"confirmation not given: {exc}\n")
            run.unconfirmed = True
            return run.finish([FleetExit.CANCELLED])
        run.clean_deferred()
        flags = frozenset(f"{REBUILD_FLAG}{short}" for short in opts.rebuild)
        approval = Approval(run.target.tag, run.target.sha,
                            {s.short: s.rolled.head for s in gated if s.rolled and s.rolled.head}, flags)
        lost = run.land(approval, deploy, hold_ring_2=hold_ring_2)
        if lost is not None:
            return lost
        return run.finish()
    finally:
        lock.release()


def run_release(deps: Deps, cfg: FleetConfig, opts: Options, *, lock_update: bool, running_sha: str,
                typed: str) -> FleetExit:
    """plan -> roll every BUMP of both rings (local) -> one confirmation -> land ring 1 -> land ring 2."""
    return _run(deps, cfg, opts, command="release", lock_update=lock_update, running_sha=running_sha,
                typed=typed, needs_flag=True, roll_new=True, rings=(1, 2), hold_ring_2=opts.hold_ring_2)


def run_land(deps: Deps, cfg: FleetConfig, opts: Options, *, lock_update: bool, running_sha: str,
             typed: str) -> FleetExit:
    """Resume a stopped run or land the held ring 2: rolls nothing new, re-gates leftovers, asks its own confirmation."""
    return _run(deps, cfg, opts, command="land", lock_update=lock_update, running_sha=running_sha, typed=typed,
                needs_flag=bool(opts.rebuild), roll_new=False, rings=opts.rings or (1, 2), hold_ring_2=False)
