"""Ring order, the canary rule, live ring-2 derivation and the confirmation table (spec 6.8)."""

from __future__ import annotations

import dataclasses
import re
from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Mapping, Sequence

from .ci import _is_billing_not_run
from .config import Consumer, FleetConfig
from .gh import Gh, GhNotFound
from .land import Lander, Outcome, RebuildBlocked
from .ledger import Record
from .plan import PlanRow
from .roll import Rolled, prepare
from .target import Target

QUEUED = frozenset({"queued", "in_progress", "waiting", "requested", "pending"})
_FAIL_STEPS = ("verify", "push-run")


@dataclass(frozen=True)
class ConsumerState:
    short: str
    ring: int
    plan: PlanRow
    rolled: Rolled | None
    outcome: Outcome | None


def _resume_ring_2(tag: str) -> str:
    return f"guard-fleet land {tag} --ring 2"


def _outcome(short: str, state: str, step: str, reason: str, next_command: str | None = None) -> Outcome:
    return Outcome(short, state, step, reason, None, None, next_command, False)   # type: ignore[arg-type]


# -- the canary rule ---------------------------------------------------------------------------------------------


def canary_block(cfg: FleetConfig, states: Sequence[ConsumerState]) -> str | None:
    """Why no other ring-1 consumer may merge: a canary is an unlanded BUMP. None for SKIP or a landed canary."""
    by_short = {s.short: s for s in states}
    for c in cfg.canaries(1):
        s = by_short.get(c.short)
        if s is None:
            return f"canary {c.short} is not part of this run (left out by --only)"
        if s.plan.decision == "SKIP":
            continue
        out = s.outcome
        if out is not None:
            if out.state == "LANDED":
                continue
            return f"canary {c.short} is {out.state} at {out.step}: {out.reason}"
        if s.plan.decision == "BLOCKED":
            return f"canary {c.short} is BLOCKED at plan: {s.plan.reason}"
        if s.rolled is not None and s.rolled.state == "BLOCKED":
            return f"canary {c.short} is BLOCKED at roll: {s.rolled.step}: {s.rolled.reason}"
        return f"canary {c.short} is NOT RUN: its bump has not landed"
    return None


# -- ring 2, derived live ----------------------------------------------------------------------------------------


def _recorded_failure(records: Sequence[Record], short: str) -> str | None:
    """A verify or push-run "fail" with no later "pass" of the same step for the same head, from any process."""
    open_failures: dict[tuple[str, str | None], str] = {}
    for r in records:
        if r.consumer != short or r.step not in _FAIL_STEPS:
            continue
        verdict = r.detail.get("verdict")
        if verdict == "fail":
            open_failures[(r.step, r.head)] = str(r.detail.get("reason") or "")
        elif verdict == "pass":
            open_failures.pop((r.step, r.head), None)
    if not open_failures:
        return None
    (step, head), reason = next(iter(open_failures.items()))
    return f"{step} failed at {(head or '?')[:12]}" + (f": {reason}" if reason else "")


def _green_push_run(records: Sequence[Record], short: str, merge: str | None) -> bool:
    verdicts = [r.detail.get("verdict") for r in records
                if r.consumer == short and r.step == "push-run" and r.detail.get("merge") == merge]
    return bool(verdicts) and verdicts[-1] == "pass"


def ring2_ready(lander: Lander, cfg: FleetConfig, target: Target) -> tuple[bool, str]:
    """Ring 2 may start: ring 1 verified live or BLOCKED, none FAILED, the canary green or SKIP. Mutates nothing."""
    records, _ = lander.ctx.ledger.records()
    ring1 = cfg.ring_order(1)
    for c in ring1:
        failure = _recorded_failure(records, c.short)
        if failure:
            return False, f"{c.short} FAILED ({failure})"
    canaries = {c.short for c in cfg.canaries(1)}
    for c in ring1:
        out = lander.merged_verified(c)
        if out.state == "FAILED":
            return False, f"{c.short} FAILED at {out.step}: {out.reason}"
        if c.short not in canaries:
            continue   # a BLOCKED ring-1 consumer is listed by the caller and does not hold ring 2
        if out.state == "LANDED":
            if not _green_push_run(records, c.short, out.merge_sha):
                return False, f"canary {c.short} landed without a green push-run gate recorded for {target.tag}"
        elif any(r.consumer == c.short and r.step == "attempt-start" for r in records):
            return False, f"canary {c.short} is not landed: {out.reason}"   # no attempt at all = SKIP
    return True, ""


# -- landing -----------------------------------------------------------------------------------------------------


def rebuild_state(lander: Lander, consumer: Consumer, state: ConsumerState) -> ConsumerState:
    """--rebuild: reset the fleet's local leftovers, then roll afresh; a refusal is a BLOCKED state, never raised."""
    try:
        lander.rebuild_local(consumer)
    except RebuildBlocked as exc:
        return dataclasses.replace(state, outcome=_outcome(state.short, "BLOCKED", "rebuild", str(exc)))
    return dataclasses.replace(state, rolled=prepare(lander.ctx, consumer, state.plan), outcome=None)


def _land_one(lander: Lander, c: Consumer, s: ConsumerState, *, canary: bool) -> Outcome:
    decision = s.plan.decision
    if decision == "BLOCKED":
        return _outcome(c.short, "BLOCKED", "plan", f"plan: {s.plan.reason}")
    if decision == "CURRENT":
        return lander.reverify_current(c, canary=canary)   # a canary's push-run gate is re-checked live
    rolled = s.rolled
    if rolled is None:
        return _outcome(c.short, "BLOCKED", "roll", "not rolled")
    if rolled.state != "GATED":
        return _outcome(c.short, "BLOCKED", "roll", f"{rolled.step}: {rolled.reason}", rolled.manual_step)
    out = lander.land_consumer(c, rolled)
    if canary and out.state == "LANDED":
        assert out.merge_sha is not None
        gate = lander.push_run_gate(c, out.merge_sha)   # before any other ring-1 publish
        if gate is not None:
            out = dataclasses.replace(gate, pr_url=out.pr_url)
    return out


def land_rings(lander: Lander, cfg: FleetConfig, target: Target, states: list[ConsumerState], *,
               rings: Sequence[int], hold_ring_2: bool) -> list[ConsumerState]:
    states = list(states)
    index = {s.short: i for i, s in enumerate(states)}
    tag = target.tag

    def put(short: str, outcome: Outcome) -> None:
        states[index[short]] = dataclasses.replace(states[index[short]], outcome=outcome)

    def pending(ring: int) -> list[Consumer]:
        return [c for c in cfg.ring_order(ring) if c.short in index and states[index[c.short]].outcome is None
                and states[index[c.short]].plan.decision != "SKIP"]

    def stop(failed: Outcome) -> list[ConsumerState]:
        for ring in rings:
            for c in pending(ring):
                put(c.short, _outcome(c.short, "NOT_RUN", "stopped", f"stopped: {failed.short} FAILED at "
                                      f"{failed.step}", f"guard-fleet land {tag}"))
        return states

    canaries = {c.short for c in cfg.canaries(1)}
    if 1 in rings:
        for c in pending(1):
            s = states[index[c.short]]
            is_canary = c.short in canaries
            why = None if is_canary else canary_block(cfg, states)
            out = _outcome(c.short, "BLOCKED", "canary", why) if why else _land_one(lander, c, s, canary=is_canary)
            put(c.short, out)
            if out.state == "FAILED":
                return stop(out)
    if 2 in rings:
        members = pending(2)
        if hold_ring_2:
            for c in members:
                put(c.short, _outcome(c.short, "HELD", "hold", "held by --hold-ring-2", _resume_ring_2(tag)))
        elif members:
            why = canary_block(cfg, states) if 1 in rings else None
            if why is None:
                ready, why = ring2_ready(lander, cfg, target)
                why = None if ready else why
            for c in members:
                if why:
                    put(c.short, _outcome(c.short, "BLOCKED", "ring2", f"ring 2 is not ready: {why}",
                                          _resume_ring_2(tag)))
                    continue
                out = _land_one(lander, c, states[index[c.short]], canary=False)
                put(c.short, out)
                if out.state == "FAILED":
                    return stop(out)
    return states


# -- the confirmation table --------------------------------------------------------------------------------------


def render_confirmation(target: Target, running_sha: str, states: Sequence[ConsumerState], *,
                        prs_to_open: Sequence[str], prs_to_close: Sequence[str], canary_order: Sequence[str],
                        deploy_lines: Sequence[str], billing: str, notes: Mapping[str, str],
                        diff_lines: Sequence[str], rebuild_commits: Mapping[str, Sequence[str]],
                        cfg: FleetConfig | None = None) -> str:
    """The table printed before the confirmation (spec 6.8). `cfg` supplies each consumer's ci and commit_env."""
    out = [f"Release {target.tag}: T {target.sha}, running fleet {running_sha[:12]}", ""]
    header = ("CONSUMER", "RING", "CI", "DECISION", "H")
    rows = []
    for s in states:
        c = cfg.by_short(s.short) if cfg is not None and any(x.short == s.short for x in cfg.consumers) else None
        head = s.rolled.head[:12] if s.rolled is not None and s.rolled.head else "-"
        rows.append((s.short, str(s.ring), c.ci if c else "-", s.plan.decision, head))
    widths = [max(len(r[i]) for r in (header, *rows)) for i in range(len(header))]
    out += ["  ".join(cell.ljust(w) for cell, w in zip(r, widths)).rstrip() for r in (header, *rows)]
    for s in states:
        c = cfg.by_short(s.short) if cfg is not None and any(x.short == s.short for x in cfg.consumers) else None
        out += ["", f"{s.short}:"]
        if s.rolled is not None:
            out += [f"  {gate}: {verdict}" for gate, (verdict, _log) in sorted(s.rolled.gates.items())]
            out.append(f"  {s.rolled.hooks}")
        else:
            out.append("  no roll")
        env = ", ".join(f"{k}={v}" for k, v in sorted((c.commit_env if c else {}).items()))
        out.append(f"  commit_env: {env or 'none'}")
    out += ["", "PRs to open:", *[f"  {line}" for line in prs_to_open or ["none"]]]
    out += ["PRs to close (superseded):", *[f"  {line}" for line in prs_to_close or ["none"]]]
    decisions = {s.short: s.plan.decision for s in states}
    if canary_order and all(decisions.get(short) == "SKIP" for short in canary_order):
        out.append("canary order: no canary ran (every canary is SKIP at this tag)")
    else:
        out.append(f"canary order: {', '.join(canary_order) or 'none'}")
    out += ["", "Deploy:", *[f"  {line}" for line in deploy_lines or ["none"]]]
    out.append(billing)
    if notes:
        out += ["", "Notes:", *[f"  {short}: {note}" for short, note in notes.items() if note]]
    if diff_lines:
        out += ["", "Differences (--diff):", *[f"  {line}" for line in diff_lines]]
    for short, commits in rebuild_commits.items():
        out += ["", f"--rebuild {short}: the remote branch would be replaced over these commits:",
                *[f"  {line}" for line in commits or ["(a head the ledger recorded)"]]]
    return "\n".join(out) + "\n"


# -- live deploy and billing state -------------------------------------------------------------------------------


def _scalars(value: str) -> list[str]:
    return [v.strip().strip("'\"") for v in value.strip().strip("[]").split(",") if v.strip()]


def _filter(children: Sequence[tuple[int, str]], key: str) -> list[str] | None:
    """The values of `key:` among the (indent, text) lines of one block; None when the key is absent."""
    if not children:
        return None
    base = children[0][0]
    for i, (indent, body) in enumerate(children):
        m = re.fullmatch(rf"{re.escape(key)}\s*:\s*(.*)", body)
        if indent != base or not m:
            continue
        if m.group(1):
            return _scalars(m.group(1))
        items = []
        for deeper, text in children[i + 1:]:
            if deeper <= base:
                break
            if text.startswith("- "):
                items.append(text[2:].strip().strip("'\""))
        return items
    return None


def triggers_on_push(text: str, branch: str) -> bool:
    """Does the workflow file run on a push to `branch`? A small reader of the common `on:` shapes, not YAML."""
    lines = []
    for raw in text.splitlines():
        body = re.sub(r"(^|\s+)#.*$", "", raw).strip()
        if body:
            lines.append((len(raw) - len(raw.lstrip(" ")), body))
    for i, (indent, body) in enumerate(lines):
        m = re.fullmatch(r"""["']?on["']?\s*:\s*(.*)""", body)
        if indent == 0 and m:
            break
    else:
        return False
    rest = m.group(1)
    if rest:
        if rest.startswith("{"):
            return re.search(r"\bpush\b", rest) is not None   # a flow map: its filters are not evaluated
        return "push" in _scalars(rest)
    block = []
    for indent, body in lines[i + 1:]:
        if indent == 0:
            break
        block.append((indent, body))
    if not block:
        return False
    base = block[0][0]
    if any(indent == base and body.strip("- '\"") == "push" and body.startswith("-") for indent, body in block):
        return True
    for j, (indent, body) in enumerate(block):
        m = re.fullmatch(r"push\s*:\s*(.*)", body)
        if indent != base or not m:
            continue
        inline = m.group(1)
        deeper = []
        for d_indent, d_body in block[j + 1:]:
            if d_indent <= base:
                break
            deeper.append((d_indent, d_body))
        if inline.startswith("{"):
            found = re.search(r"branches\s*:\s*\[([^\]]*)\]", inline)
            return True if not found else any(fnmatchcase(branch, p) for p in _scalars(found.group(1)))
        branches, ignored = _filter(deeper, "branches"), _filter(deeper, "branches-ignore")
        if branches is not None:
            return any(fnmatchcase(branch, p) for p in branches)
        if ignored is not None:
            return not any(fnmatchcase(branch, p) for p in ignored)
        return _filter(deeper, "tags") is None and _filter(deeper, "tags-ignore") is None
    return False


def deploy_lines(gh: Gh, cfg: FleetConfig, d_by_short: Mapping[str, str]) -> list[str]:
    """The deploy workflows' live state and queue, and which merges deploy at once; read only, from live state."""
    lines: list[str] = []
    for c in cfg.consumers:
        for wf in c.deploy_workflows:
            try:
                state = gh.workflow_state(c.slug, wf)
            except GhNotFound:
                lines.append(f"{c.short}: deploy {wf}: not found")
                continue
            queue = [r for r in gh.run_list(c.slug, workflow=wf, branch=c.default_branch)
                     if str(r.get("status") or "").lower() in QUEUED]
            shown = ", ".join(f"#{r.get('databaseId')} {r.get('status')}" for r in queue)
            lines.append(f"{c.short}: deploy {wf}: {state}; {len(queue)} queued or running on {c.default_branch}"
                         + (f" ({shown})" if shown else ""))
            if state != "active":
                continue
            raw = gh.contents_raw(c.slug, f".github/workflows/{wf}", d_by_short.get(c.short, c.default_branch))
            if raw is not None and triggers_on_push(raw.decode("utf-8", errors="replace"), c.default_branch):
                lines.append(f"{c.short}: merging deploys to production ({wf} on push to {c.default_branch})")
    return lines


def billing_state(gh: Gh, cfg: FleetConfig) -> str:
    """The newest workflow run on each default branch: a job refused for unpaid billing blocks that consumer."""
    blocked: list[str] = []
    for c in cfg.consumers:
        runs = sorted(gh.run_list(c.slug, branch=c.default_branch), key=lambda r: str(r.get("createdAt") or ""),
                      reverse=True)
        if not runs:
            continue
        for job in gh.run_jobs(c.slug, int(runs[0]["databaseId"])):
            if str(job.get("conclusion") or "").lower() != "failure" or not isinstance(job.get("id"), int):
                continue
            try:
                notes = gh.check_run_annotations(c.slug, job["id"])
            except GhNotFound:
                continue
            if _is_billing_not_run(job, notes) is not None:
                blocked.append(c.short)
                break
    return f"Actions billing blocked: {', '.join(blocked)}" if blocked else "Actions billing: ok"
