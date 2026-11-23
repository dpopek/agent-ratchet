"""CI classification of a PR's checks with a closed whitelist, and the wait loop around it."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal

from .deps import Deps
from .gh import Gh

BILLING_PREFIX = "The job was not started because recent account payments have failed"

CheckVerdict = Literal["pass", "not_run", "pending", "blocks"]

SETTLE_SECONDS = 60.0
POLL_START = 15.0
POLL_CEILING = 60.0
_PENDING_STATUSES = frozenset({"queued", "in_progress", "waiting", "requested", "pending"})
_PASS_CONCLUSIONS = frozenset({"success", "neutral", "skipped"})
_JOB_URL_RE = re.compile(r"/job/(\d+)")


@dataclass(frozen=True)
class Check:
    name: str
    kind: Literal["check_run", "status_context"]
    verdict: CheckVerdict
    detail: str
    success: bool


def check_run_id(entry: Mapping) -> int | None:
    """The check-run id: `databaseId`, else the job id in `detailsUrl` (gh's rollup omits databaseId)."""
    raw = entry.get("databaseId")
    if isinstance(raw, int):
        return raw
    m = _JOB_URL_RE.search(str(entry.get("detailsUrl") or ""))
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
                        annotations: Mapping[int, Sequence[dict]]) -> Check:
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
        cid = check_run_id(entry)
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


def classify_rollup(rollup: Sequence[dict], jobs_by_check: Mapping[int, dict],
                    annotations_by_check: Mapping[int, Sequence[dict]]) -> list[Check]:
    latest: dict[tuple[str, str], dict] = {}
    for entry in rollup:
        if entry.get("__typename") == "StatusContext":
            key = ("status_context", str(entry.get("context") or ""))
            order = (str(entry.get("createdAt") or ""), "")
        else:
            key = ("check_run", str(entry.get("name") or ""))
            order = (str(entry.get("startedAt") or ""), str(entry.get("completedAt") or ""))
        held = latest.get(key)
        if held is None or order >= held["_order"]:
            latest[key] = {"_order": order, "entry": entry}
    checks = []
    for (kind, _), item in latest.items():
        entry = item["entry"]
        checks.append(_classify_status_context(entry) if kind == "status_context"
                      else _classify_check_run(entry, jobs_by_check, annotations_by_check))
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


def _app_key(entry: Mapping) -> str | None:
    """App identity of a check run, matching `check_suites[].app.slug`.

    gh's rollup carries no app field; a CheckRun with a `workflowName` is produced by GitHub Actions
    (slug `github-actions`). An explicit `app.slug` wins when present. None = unknown app.
    """
    app = entry.get("app")
    if isinstance(app, Mapping) and app.get("slug"):
        return str(app["slug"])
    return "github-actions" if entry.get("workflowName") else None


def _suites_cover(gh: Gh, slug: str, head: str, rollup: Sequence[dict]) -> bool:
    keys = [_app_key(e) for e in rollup if e.get("__typename") != "StatusContext"]
    if not keys or None in keys:
        return False  # no reliable key: fall back to the time/stability clause only
    suites = gh.api(f"repos/{slug}/commits/{head}/check-suites").json().get("check_suites", [])
    present = {str((s.get("app") or {}).get("slug")) for s in suites}
    return set(keys) <= present


def wait_for_ci(deps: Deps, gh: Gh, slug: str, number: int, head: str, *,
                mode: Literal["if-run", "required"], cap_min: int, pushed_at_mono: float
                ) -> tuple[Literal["pass", "blocks", "timeout"], list[Check]]:
    deadline: float | None = None
    previous: list[tuple[str, str]] | None = None
    delay = POLL_START
    checks: list[Check] = []
    jobs: dict[int, dict] = {}
    notes: dict[int, list[dict]] = {}
    while True:
        view = gh.pr_view(slug, number, ["headRefOid", "statusCheckRollup"])
        now = deps.clock.monotonic()
        if deadline is None:
            deadline = now + cap_min * 60
        rollup = view.get("statusCheckRollup") or []
        if view.get("headRefOid") == head:
            for entry in rollup:
                cid = check_run_id(entry)
                if (cid is not None and cid not in jobs and entry.get("__typename") != "StatusContext"
                        and str(entry.get("status") or "").lower() == "completed"
                        and str(entry.get("conclusion") or "").lower() == "failure"):
                    jobs[cid] = gh.job(slug, cid)
                    notes[cid] = gh.check_run_annotations(slug, cid)
            checks = classify_rollup(rollup, jobs, notes)
            overall = verdict(checks, mode)
            signature = sorted((c.name, c.verdict) for c in checks)
            if overall != "pending":
                stable = now - pushed_at_mono >= SETTLE_SECONDS and signature == previous
                if stable or _suites_cover(gh, slug, head, rollup):
                    return overall, checks
            previous = signature
        else:
            previous = None  # the PR head is not ours yet: the rollup belongs to another commit
        if now >= deadline:
            return "timeout", checks
        deps.sleep(min(delay, deadline - now))
        delay = min(delay * 2, POLL_CEILING)
