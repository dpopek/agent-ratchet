"""CI classification of a PR's checks with a closed whitelist, and the wait loop around it."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal

from .deps import Deps
from .gh import Gh, GhNotFound

BILLING_PREFIX = "The job was not started because recent account payments have failed"

CheckVerdict = Literal["pass", "not_run", "pending", "blocks"]

SETTLE_SECONDS = 60.0
POLL_START = 15.0
POLL_CEILING = 60.0
_PENDING_STATUSES = frozenset({"queued", "in_progress", "waiting", "requested", "pending"})
_PASS_CONCLUSIONS = frozenset({"success", "neutral", "skipped"})


@dataclass(frozen=True)
class Check:
    name: str
    kind: Literal["check_run", "status_context"]
    verdict: CheckVerdict
    detail: str
    success: bool


def check_run_id(entry: Mapping, slug: str | None = None) -> int | None:
    """The check-run id: `databaseId`, else the job id of a GitHub Actions `detailsUrl` of this repo.

    gh's rollup omits databaseId; non-Actions checks (other hosts, other repos) yield None.
    """
    raw = entry.get("databaseId")
    if isinstance(raw, int) and not isinstance(raw, bool):
        return raw
    if slug is None:
        return None
    m = re.fullmatch(rf"https://github\.com/{re.escape(slug)}/actions/runs/\d+/job/(\d+)",
                     str(entry.get("detailsUrl") or ""))
    return int(m.group(1)) if m else None


def _is_billing_not_run(job: Mapping | None, annotations: Sequence[Mapping]) -> str | None:
    if job is None:
        return None
    if job.get("runner_id") != 0 or job.get("runner_name") != "" or job.get("runner_group_id") != 0:
        return None
    if job.get("steps") != []:
        return None
    for ann in annotations:
        message = str(ann.get("message") or "")
        if str(ann.get("annotation_level") or "").lower() == "failure" and message.startswith(BILLING_PREFIX):
            return message
    return None


def _classify_check_run(entry: Mapping, jobs: Mapping[int, dict],
                        annotations: Mapping[int, Sequence[dict]], slug: str | None) -> Check:
    name = str(entry.get("name") or "")
    status = str(entry.get("status") or "").lower()
    conclusion = str(entry.get("conclusion") or "").lower()
    if status != "completed":
        if status in _PENDING_STATUSES:
            return Check(name, "check_run", "pending", status, False)
        return Check(name, "check_run", "blocks", f"unknown status {status!r}", False)
    if conclusion in _PASS_CONCLUSIONS:
        return Check(name, "check_run", "pass", conclusion, conclusion == "success")
    if conclusion == "failure":
        cid = check_run_id(entry, slug)
        if cid is not None:
            billing = _is_billing_not_run(jobs.get(cid), annotations.get(cid, ()))
            if billing is not None:
                return Check(name, "check_run", "not_run", billing, False)
    return Check(name, "check_run", "blocks", conclusion or "no conclusion", False)


def _classify_status_context(entry: Mapping) -> Check:
    name = str(entry.get("context") or "")
    state = str(entry.get("state") or "").lower()
    if state == "success":
        return Check(name, "status_context", "pass", state, True)
    if state in ("pending", "expected"):
        return Check(name, "status_context", "pending", state, False)
    return Check(name, "status_context", "blocks", state or "no state", False)


_WORST = {"blocks": 3, "pending": 2, "not_run": 1, "pass": 0}


def _stamp(*values: object) -> str:
    """Sort key of a timestamp; missing or zero (not yet started) counts as newest."""
    for v in values:
        text = str(v or "")
        if text and not text.startswith("0001-"):
            return text
    return "\uffff"


def classify_rollup(rollup: Sequence[dict], jobs_by_check: Mapping[int, dict],
                    annotations_by_check: Mapping[int, Sequence[dict]], *,
                    slug: str | None = None) -> list[Check]:
    """Latest attempt per check; equal-newest duplicates resolve to the worst verdict."""
    groups: dict[tuple[str, str], list[tuple[tuple[str, str], dict]]] = {}
    for entry in rollup:
        if entry.get("__typename") == "StatusContext":
            key = ("status_context", str(entry.get("context") or ""))
            order = (_stamp(entry.get("startedAt"), entry.get("createdAt")), "")
        else:
            key = ("check_run", str(entry.get("name") or ""))
            started = _stamp(entry.get("startedAt"))
            order = (started, "" if started == "\uffff" else str(entry.get("completedAt") or ""))
        groups.setdefault(key, []).append((order, entry))
    checks = []
    for (kind, _), items in groups.items():
        newest = max(o for o, _ in items)
        cands = [_classify_status_context(e) if kind == "status_context"
                 else _classify_check_run(e, jobs_by_check, annotations_by_check, slug)
                 for o, e in items if o == newest]
        checks.append(max(cands, key=lambda c: _WORST[c.verdict]))
    return checks


def verdict(checks: Sequence[Check], mode: Literal["if-run", "required"]) -> Literal["pass", "pending", "blocks"]:
    if any(c.verdict == "blocks" for c in checks):
        return "blocks"
    if any(c.verdict == "pending" for c in checks):
        return "pending"
    if mode == "if-run":
        return "pass"
    if any(c.success for c in checks):
        return "pass"
    return "pending" if not checks else "blocks"


def wait_for_ci(deps: Deps, gh: Gh, slug: str, number: int, head: str, *,
                mode: Literal["if-run", "required"], cap_min: int, pushed_at_mono: float
                ) -> tuple[Literal["pass", "blocks", "timeout"], list[Check]]:
    cap = cap_min * 60
    deadline: float | None = None  # starts at the first poll on `head`; until then, at the first poll
    matched = False
    previous: list[tuple[str, str]] | None = None
    delay = POLL_START
    checks: list[Check] = []
    jobs: dict[int, dict] = {}
    notes: dict[int, list[dict]] = {}
    unfetchable: set[int] = set()
    while True:
        view = gh.pr_view(slug, number, ["headRefOid", "statusCheckRollup"])
        now = deps.clock.monotonic()
        if deadline is None:
            deadline = now + cap
        if view.get("headRefOid") == head:
            if not matched:
                matched = True
                deadline = now + cap  # first classification
            rollup = view.get("statusCheckRollup") or []
            for entry in rollup:
                cid = check_run_id(entry, slug)
                if (cid is not None and cid not in jobs and cid not in unfetchable
                        and entry.get("__typename") != "StatusContext"
                        and str(entry.get("status") or "").lower() == "completed"
                        and str(entry.get("conclusion") or "").lower() == "failure"):
                    try:
                        jobs[cid] = gh.job(slug, cid)
                        notes[cid] = gh.check_run_annotations(slug, cid)
                    except GhNotFound:
                        jobs.pop(cid, None)
                        unfetchable.add(cid)  # no billing exemption: the check blocks
            checks = classify_rollup(rollup, jobs, notes, slug=slug)
            overall = verdict(checks, mode)
            signature = sorted((c.name, c.verdict) for c in checks)
            if (overall != "pending" and now - pushed_at_mono >= SETTLE_SECONDS
                    and signature == previous):
                return overall, checks
            previous = signature
        else:
            previous = None  # the PR head is not ours yet: the rollup belongs to another commit
        assert deadline is not None
        if now >= deadline:
            return "timeout", checks
        deps.sleep(min(delay, deadline - now))
        delay = min(delay * 2, POLL_CEILING)
