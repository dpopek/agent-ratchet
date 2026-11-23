from __future__ import annotations

import pytest

from guard_fleet.ci import BILLING_PREFIX, Check, classify_rollup, verdict, wait_for_ci
from fakes import make_deps


def cr(db_id, name, status, conclusion=None, started="2026-11-22T10:00:00Z", completed="", workflow="CI"):
    return {"__typename": "CheckRun", "databaseId": db_id, "name": name, "status": status,
            "conclusion": conclusion, "startedAt": started, "completedAt": completed,
            "workflowName": workflow}


def sc(context, state):
    return {"__typename": "StatusContext", "context": context, "state": state}


def test_billing_not_run_requires_all_markers():
    job = {"runner_id": 0, "runner_name": "", "runner_group_id": 0, "steps": []}
    ann = [{"annotation_level": "failure", "message": BILLING_PREFIX + " or your spending limit"}]
    first = classify_rollup([cr(1, "test", "COMPLETED", "FAILURE")], {1: job}, {1: ann})[0]
    assert first.verdict == "not_run" and first.detail.startswith(BILLING_PREFIX) and not first.success
    assert classify_rollup([cr(1, "test", "COMPLETED", "FAILURE")], {1: job | {"steps": [{}]}}, {1: ann})[0].verdict == "blocks"
    assert classify_rollup([cr(1, "test", "COMPLETED", "FAILURE")], {1: job | {"runner_id": 7}}, {1: ann})[0].verdict == "blocks"
    warn = [{"annotation_level": "warning", "message": BILLING_PREFIX}]
    assert classify_rollup([cr(1, "test", "COMPLETED", "FAILURE")], {1: job}, {1: warn})[0].verdict == "blocks"
    assert classify_rollup([cr(1, "test", "COMPLETED", "FAILURE")], {}, {})[0].verdict == "blocks"


@pytest.mark.parametrize("conclusion", ["CANCELLED", "STARTUP_FAILURE", "TIMED_OUT", "ACTION_REQUIRED", "STALE", "FAILURE"])
def test_other_conclusions_block(conclusion):
    assert classify_rollup([cr(1, "t", "COMPLETED", conclusion)], {1: {"steps": [{}]}}, {})[0].verdict == "blocks"


def test_pass_pending_and_success_flags():
    checks = classify_rollup([cr(1, "a", "COMPLETED", "SUCCESS"), cr(2, "b", "COMPLETED", "NEUTRAL"),
                              cr(3, "c", "COMPLETED", "SKIPPED"), cr(4, "d", "IN_PROGRESS"),
                              cr(5, "e", "QUEUED"), cr(6, "f", "WAITING")], {}, {})
    assert [(c.verdict, c.success) for c in checks] == [
        ("pass", True), ("pass", False), ("pass", False), ("pending", False), ("pending", False), ("pending", False)]


def test_rerun_replaces_earlier_attempt():
    rollup = [cr(1, "t", "COMPLETED", "FAILURE", started="2026-11-22T10:00:00Z"),
              cr(2, "t", "COMPLETED", "SUCCESS", started="2026-11-22T10:05:00Z")]
    assert [c.verdict for c in classify_rollup(rollup, {1: {"steps": [{}]}}, {})] == ["pass"]
    assert [c.verdict for c in classify_rollup(rollup[::-1], {1: {"steps": [{}]}}, {})] == ["pass"]


def test_if_run_passes_on_empty_or_billing_only_and_required_needs_success():
    assert verdict([], "if-run") == "pass" and verdict([], "required") == "pending"
    assert verdict([Check("t", "check_run", "not_run", "", False)], "if-run") == "pass"
    assert verdict([Check("t", "check_run", "not_run", "", False)], "required") == "blocks"
    assert verdict([Check("t", "check_run", "pass", "", False), Check("u", "check_run", "pass", "", False)], "required") == "blocks"
    assert verdict([Check("t", "check_run", "pass", "", True)], "required") == "pass"
    assert verdict([Check("t", "check_run", "pass", "", True), Check("u", "check_run", "blocks", "", False)], "required") == "blocks"
    assert verdict([Check("t", "check_run", "pass", "", True), Check("u", "check_run", "pending", "", False)], "if-run") == "pending"


def test_pending_status_context_is_pending():
    for state in ("PENDING", "EXPECTED"):
        (c,) = classify_rollup([sc("ci/x", state)], {}, {})
        assert (c.kind, c.verdict) == ("status_context", "pending")
    for state in ("FAILURE", "ERROR"):
        assert classify_rollup([sc("ci/x", state)], {}, {})[0].verdict == "blocks"
    ok = classify_rollup([sc("ci/x", "SUCCESS")], {}, {})[0]
    assert (ok.verdict, ok.success) == ("pass", True)


class StubGh:
    """Exposes exactly the Gh methods wait_for_ci calls, scripted per poll (last script repeats)."""

    def __init__(self, polls, head="h" * 40):
        self.polls = list(polls)
        self.head = head
        self.pr_calls = 0
        self.jobs: list[int] = []
        self.annotation_calls: list[int] = []

    def pr_view(self, slug, number, fields):
        assert list(fields) == ["headRefOid", "statusCheckRollup"]
        rollup = self.polls[min(self.pr_calls, len(self.polls) - 1)]
        self.pr_calls += 1
        return {"headRefOid": self.head, "statusCheckRollup": rollup}

    def job(self, slug, job_id):
        self.jobs.append(job_id)
        return {"runner_id": 0, "runner_name": "", "runner_group_id": 0, "steps": []}

    def check_run_annotations(self, slug, check_run_id):
        self.annotation_calls.append(check_run_id)
        return [{"annotation_level": "failure", "message": BILLING_PREFIX}]


def _run(tmp_path, gh, *, mode="if-run", cap_min=10):
    deps = make_deps(tmp_path)
    t0 = deps.clock.monotonic()
    result = wait_for_ci(deps, gh, "o/a", 5, gh.head, mode=mode, cap_min=cap_min, pushed_at_mono=t0)
    return result, deps.clock.monotonic() - t0


def test_wait_settles_before_classifying_and_times_out(tmp_path):
    passing = [cr(1, "t", "COMPLETED", "SUCCESS")]
    gh = StubGh([passing])
    (state, checks), elapsed = _run(tmp_path, gh)
    # polls at 0, 15, 45 (all < 60 s) are never returned; the identical poll at 105 s settles
    assert (state, [c.verdict for c in checks]) == ("pass", ["pass"])
    assert elapsed == 105 and gh.pr_calls == 4

    flapping = [[cr(i, f"t{i}", "COMPLETED", "SUCCESS")] for i in range(1, 40)]
    gh = StubGh(flapping)
    (state, checks), elapsed = _run(tmp_path, gh, cap_min=5)
    assert state == "timeout" and checks and elapsed == 300

    gh = StubGh([[cr(1, "t", "IN_PROGRESS")]])
    (state, checks), elapsed = _run(tmp_path, gh, cap_min=3)
    assert state == "timeout" and [c.verdict for c in checks] == ["pending"] and elapsed == 180


def test_wait_returns_blocks_and_reads_billing_only_for_failures(tmp_path):
    gh = StubGh([[cr(1, "t", "COMPLETED", "SUCCESS"), cr(2, "u", "COMPLETED", "FAILURE")]])
    (state, checks), _ = _run(tmp_path, gh, mode="required")
    assert state == "pass" and [c.verdict for c in checks] == ["pass", "not_run"]
    assert set(gh.jobs) == {2} and set(gh.annotation_calls) == {2}
    gh = StubGh([[cr(1, "t", "COMPLETED", "CANCELLED")]])
    (state, _), _ = _run(tmp_path, gh)
    assert state == "blocks" and gh.jobs == [] and gh.annotation_calls == []


def test_pass_before_settle_window_is_never_returned(tmp_path):
    gh = StubGh([[cr(1, "t", "COMPLETED", "SUCCESS")]])
    deps = make_deps(tmp_path)
    t0 = deps.clock.monotonic()
    seen = []
    orig = gh.pr_view

    def spy(*a):
        seen.append(deps.clock.monotonic() - t0)
        return orig(*a)
    gh.pr_view = spy
    wait_for_ci(deps, gh, "o/a", 5, gh.head, mode="if-run", cap_min=10, pushed_at_mono=t0)
    assert seen == [0, 15, 45, 105]


def test_head_mismatch_never_settles_and_cap_starts_at_first_matching_poll(tmp_path):
    passing = [cr(1, "t", "COMPLETED", "SUCCESS")]
    class Moving(StubGh):
        def pr_view(self, slug, number, fields):
            view = super().pr_view(slug, number, fields)
            if self.pr_calls <= 3:
                view["headRefOid"] = "0" * 40
            return view
    gh = Moving([passing])
    (state, _), elapsed = _run(tmp_path, gh, cap_min=10)
    # mismatching polls at 0, 15, 45; first matching poll at 105 starts the cap; settle needs one more equal poll
    assert state == "pass" and elapsed == 165 and gh.pr_calls == 5
    gh = Moving([[cr(1, "t", "IN_PROGRESS")]])
    (state, _), elapsed = _run(tmp_path, gh, cap_min=3)
    assert (state, elapsed) == ("timeout", 105 + 180)  # cap runs from the first matching poll
    class Never(StubGh):
        def pr_view(self, slug, number, fields):
            view = super().pr_view(slug, number, fields)
            view["headRefOid"] = "0" * 40
            return view
    (state, checks), elapsed = _run(tmp_path, Never([passing]), cap_min=2)
    assert (state, checks, elapsed) == ("timeout", [], 120)


def test_detailsurl_fallback_is_anchored_to_actions_jobs_of_this_repo(tmp_path):
    url = "https://github.com/o/a/actions/runs/9/job/77"
    entry = cr(None, "t", "COMPLETED", "FAILURE") | {"databaseId": None, "detailsUrl": url}
    gh = StubGh([[entry]])
    (state, checks), _ = _run(tmp_path, gh)
    assert gh.jobs == [77] and checks[0].verdict == "not_run" and state == "pass"
    for bad in ("https://ci.example.com/x/job/77", "https://github.com/o/other/actions/runs/9/job/77", ""):
        gh = StubGh([[entry | {"detailsUrl": bad}]])
        (state, checks), _ = _run(tmp_path, gh)
        assert gh.jobs == [] and gh.annotation_calls == [] and state == "blocks"


def test_not_found_on_job_blocks_but_auth_and_network_errors_propagate(tmp_path):
    from guard_fleet.gh import GhAuthError, GhNetworkError, GhNotFound
    failing = [cr(1, "t", "COMPLETED", "FAILURE")]
    gh = StubGh([failing])
    gh.job = lambda slug, jid: (_ for _ in ()).throw(GhNotFound(404, "gone"))
    (state, checks), _ = _run(tmp_path, gh)
    assert state == "blocks" and checks[0].verdict == "blocks"
    for exc in (GhAuthError(401, "x"), GhNetworkError(None, "x")):
        gh = StubGh([failing])
        gh.job = lambda slug, jid, exc=exc: (_ for _ in ()).throw(exc)
        with pytest.raises(type(exc)):
            _run(tmp_path, gh)
        gh = StubGh([failing])
        gh.pr_view = lambda *a, exc=exc: (_ for _ in ()).throw(exc)
        with pytest.raises(type(exc)):
            _run(tmp_path, gh)


def test_unknown_values_fail_closed():
    for status, conclusion in (("COMPLETED", "MYSTERY"), ("COMPLETED", None), ("WEIRD", None)):
        assert classify_rollup([cr(1, "t", "COMPLETED", None) | {"status": status, "conclusion": conclusion}],
                               {}, {})[0].verdict == "blocks"
    assert classify_rollup([sc("c", "MYSTERY")], {}, {})[0].verdict == "blocks"


@pytest.mark.parametrize("started", ["", None, "0001-01-01T00:00:00Z"])
def test_unstarted_rerun_is_newest(started):
    old = cr(1, "t", "COMPLETED", "SUCCESS", started="2026-11-22T10:00:00Z")
    rerun = cr(2, "t", "QUEUED", None, started=started)
    for rollup in ([old, rerun], [rerun, old]):
        assert [c.verdict for c in classify_rollup(rollup, {}, {})] == ["pending"]


def test_equal_timestamps_resolve_to_worst_verdict():
    ok = cr(1, "t", "COMPLETED", "SUCCESS")
    bad = cr(2, "t", "COMPLETED", "CANCELLED")
    assert classify_rollup([bad, ok], {}, {})[0].verdict == "blocks"
    assert classify_rollup([ok, bad], {}, {})[0].verdict == "blocks"


def test_status_context_duplicates():
    old_ok = sc("c", "SUCCESS") | {"createdAt": "2026-11-22T10:00:00Z"}
    new_bad = sc("c", "FAILURE") | {"createdAt": "2026-11-22T10:05:00Z"}
    assert classify_rollup([new_bad, old_ok], {}, {})[0].verdict == "blocks"
    assert classify_rollup([old_ok, new_bad], {}, {})[0].verdict == "blocks"
    started = sc("c", "SUCCESS") | {"startedAt": "2026-11-22T10:09:00Z"}
    assert classify_rollup([started, new_bad], {}, {})[0].verdict == "pass"
    assert classify_rollup([sc("c", "SUCCESS"), sc("c", "FAILURE")], {}, {})[0].verdict == "blocks"


def test_required_with_empty_rollup_keeps_waiting(tmp_path):
    gh = StubGh([[]])
    (state, checks), elapsed = _run(tmp_path, gh, mode="required", cap_min=2)
    assert (state, checks, elapsed) == ("timeout", [], 120)
