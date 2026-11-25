"""Land one consumer against real fixture repositories: a gated roll from test_roll's builder, FakeGh for GitHub."""

import dataclasses
import json

import pytest

from fakes import Route, _http
from guard_fleet import land as land_mod
from guard_fleet.gh import GhNetworkError
from guard_fleet.git import GitError, GitNetworkError
from guard_fleet.land import GOVERNANCE_JOB, REBUILD_FLAG, Approval, Lander, RebuildBlocked
from guard_fleet.lockfile import render_lock
from guard_fleet.mirror import UPSTREAM_URL
from guard_fleet.proc import Result
from guard_fleet.roll import prepare
from repos import _git, commit_files, make_clone, redirect, sha_of
from test_roll import TAG, build_env

SLUG = "owner/alpha"
LOGIN = "operator"


class LandEnv:
    def __init__(self, tmp_path, home):
        env = build_env(tmp_path, home, "alpha")
        self.ctx, self.alpha, self.row = env
        redirect(home, UPSTREAM_URL, env.up)   # validate_target's ls-remote peel
        self.env, self.tmp, self.home = env, tmp_path, home
        self.fake = env.fake_gh
        self.bare = self.fake.bares[SLUG]
        self.clone, self.t, self.p = env.clone, env.t, env.p
        self.branch, self.wt = env.branch, env.wt
        self.rolled = prepare(self.ctx, self.alpha, self.row)
        assert self.rolled.state == "GATED", self.rolled
        self.calls = self.ctx.deps.run.calls
        self.clock = self.ctx.deps.clock
        self.lander = self.make_lander()

    def make_lander(self, *, heads=None, t=None, flags=frozenset()):
        approval = Approval(TAG, t or self.t, {"alpha": self.rolled.head} if heads is None else heads, flags)
        return Lander(self.ctx, approval, LOGIN, running_tag="v4.0.0", running_sha="f" * 40)

    def count_calls(self, needle):
        return sum(1 for argv, _, _ in self.calls if any(needle in a for a in argv))

    def gh_calls(self, *prefix):
        return [a for a, _, _ in self.calls if a[:len(prefix)] == prefix]

    def pr(self, number):
        return next(p for p in self.fake.prs.get(SLUG, []) if p["number"] == number)

    def other_clone(self, name="other"):
        return make_clone(self.bare, self.tmp / name)

    def move_main(self, files, *, rewrite=False):
        """Push a commit to the GitHub-side default branch; `rewrite` replaces main's tip (BASE drops out)."""
        work = self.other_clone(f"other-{len(list(self.tmp.glob('other-*')))}")
        if rewrite:
            _git(work, "reset", "-q", "--hard", "HEAD~1")
        commit_files(work, "upstream change", files)
        _git(work, "push", "-q", "-f", "origin", "HEAD:refs/heads/main")
        return sha_of(work, "HEAD")

    def answer_gate_ask(self, flagged=()):
        self.ctx.deps.run.routes.insert(0, Route(match=lambda a: a[:2] == ("uv", "run") and "-c" in a,
                                                 stdout=json.dumps(sorted(flagged)).encode()))

    def patch_merge(self, monkeypatch, effect):
        orig = self.fake._pr_merge

        def patched(argv, slug, env):
            return effect(orig, argv, slug, env)
        monkeypatch.setattr(self.fake, "_pr_merge", patched)

    def records(self, step):
        return [r for r in self.ctx.ledger.records()[0] if r.step == step]


@pytest.fixture
def land_env(tmp_path, fleet_home):
    return LandEnv(tmp_path, fleet_home)


@pytest.fixture
def fake_clock(land_env):
    return land_env.clock


def merge_calls(env):
    return env.gh_calls("gh", "pr", "merge")


# -- the happy path ----------------------------------------------------------------------------------------


def test_merge_argv_always_has_match_head_commit(land_env):
    out = land_env.lander.land_consumer(land_env.alpha, land_env.rolled)
    merges = [a for a, _, _ in land_env.calls if a[:3] == ("gh", "pr", "merge")]
    assert out.state == "LANDED" and merges == [("gh", "pr", "merge", "1", "--repo", "owner/alpha", "--merge",
                                                 "--match-head-commit", land_env.rolled.head)]
    merge = sha_of(land_env.bare, "main")
    assert out.merge_sha == merge and out.pr_url == f"https://github.com/{SLUG}/pull/1"
    assert _git(land_env.bare, "rev-parse", f"{merge}^2") == land_env.rolled.head
    assert [r.detail["verdict"] for r in land_env.records("verify")] == ["pass"]
    assert [r.detail["verdict"] for r in land_env.records("ci")] == ["pass"]
    # cleanup under the land approval: remote branch, worktree and local branch are gone, nothing kept
    assert not out.cleanup_kept and len(out.cleanup) == 1 and "removed" in out.cleanup[0]
    assert _git(land_env.bare, "branch", "--list", land_env.branch) == ""
    assert not land_env.wt.exists()
    body = land_env.ctx.deps.dirs.consumer_dir(TAG, "alpha") / "pr-body.md"
    assert body.stat().st_mode & 0o777 == 0o600   # the consumer dir already exists (the gate logs live there)
    assert "Opened by guard-fleet v4.0.0 (ffffffff)." in body.read_text()


def test_push_uses_an_empty_lease_from_the_worktree(land_env):
    land_env.lander.publish(land_env.alpha, land_env.rolled)
    pushes = [(a, cwd) for a, cwd, _ in land_env.calls if a[:1] == ("git",) and "push" in a]
    assert len(pushes) == 1
    argv, cwd = pushes[0]
    assert argv[argv.index("push"):] == ("push", f"--force-with-lease=refs/heads/{land_env.branch}:", "origin",
                                         f"{land_env.rolled.head}:refs/heads/{land_env.branch}")
    assert cwd == land_env.wt and "--no-verify" not in argv


def test_pre_push_hook_refusal_blocks_and_opens_no_pr(land_env):
    hook = land_env.clone / ".git" / "hooks" / "pre-push"
    hook.write_text("#!/bin/sh\necho no >&2\nexit 1\n")
    hook.chmod(0o755)
    out = land_env.lander.land_consumer(land_env.alpha, land_env.rolled)
    assert (out.state, out.step, out.reason) == ("BLOCKED", "publish", "push: pre-push hook refused")
    assert land_env.gh_calls("gh", "pr", "create") == [] and land_env.wt.is_dir()


# -- fail-closed checks before the merge ---------------------------------------------------------------------


WHERE_WORDS = {"ledger": "the ledger has no gated attempt on H", "branch": "local", "pr": "the PR head"}


@pytest.mark.parametrize("where", ["ledger", "branch", "pr"])
def test_head_mismatch_blocks(land_env, where):
    number, _, _ = land_env.lander.publish(land_env.alpha, land_env.rolled)
    h = land_env.rolled.head
    if where == "ledger":   # a newer attempt that never finished: the gated one is no longer the latest
        land_env.ctx.ledger.start_attempt("alpha", land_env.rolled.base)
    elif where == "branch":
        _git(land_env.clone, "update-ref", f"refs/heads/{land_env.branch}", f"{h}^")
    else:
        land_env.pr(number)["headRefOid"] = "e" * 40
    out = land_env.lander.premerge(land_env.alpha, land_env.rolled, number)
    assert out is not None and (out.state, out.step) == ("BLOCKED", "premerge")
    assert f"head mismatch: {WHERE_WORDS[where]}" in out.reason
    assert land_env.pr(number)["state"] == "CLOSED" and not out.keep_pr_open
    assert "head mismatch" in land_env.fake.closed_comments[(SLUG, number)]
    assert merge_calls(land_env) == []


def test_lock_bytes_at_h_must_be_t_plus_extras(land_env):
    h = land_env.rolled.head
    land_env.ctx.deps.run.routes.insert(0, Route(
        match=lambda a: a[:2] == ("gh", "api") and a[-1] == f"repos/{SLUG}/contents/guard.lock?ref={h}",
        effect=lambda *_: _http(200, render_lock(land_env.t, "none"))))   # T without alpha's EXTRAS=php
    out = land_env.lander.land_consumer(land_env.alpha, land_env.rolled)
    assert (out.state, out.step) == ("BLOCKED", "premerge") and "guard.lock at H" in out.reason
    assert repr(render_lock(land_env.t, "php")) in out.reason
    assert land_env.pr(1)["state"] == "CLOSED" and merge_calls(land_env) == []


def test_premerge_reruns_shape_and_tag_validation(land_env):
    number, _, _ = land_env.lander.publish(land_env.alpha, land_env.rolled)
    stale = land_env.make_lander(t="a" * 40)   # the approval bound another peel
    out = stale.premerge(land_env.alpha, land_env.rolled, number)
    assert out is not None and out.state == "BLOCKED" and "target" in out.reason and out.keep_pr_open
    land_env.fake.merge_commit_allowed[SLUG] = False
    out = land_env.lander.premerge(land_env.alpha, land_env.rolled, number)
    assert out is not None and "merge commits are not allowed" in out.reason
    assert land_env.pr(number)["state"] == "OPEN"


@pytest.mark.parametrize("mergeable,status,blocked", [
    ("MERGEABLE", "UNSTABLE", False), ("MERGEABLE", "HAS_HOOKS", False), ("CONFLICTING", "DIRTY", True),
    ("MERGEABLE", "BLOCKED", True), ("UNKNOWN", "CLEAN", True)])
def test_mergeability_needs_mergeable_and_an_ok_state(land_env, mergeable, status, blocked):
    number, _, _ = land_env.lander.publish(land_env.alpha, land_env.rolled)
    land_env.pr(number).update(mergeable=mergeable, mergeStateStatus=status)
    start = land_env.clock.monotonic()
    out = land_env.lander.premerge(land_env.alpha, land_env.rolled, number)
    assert (out is not None) is blocked
    if blocked:
        assert out.keep_pr_open and land_env.pr(number)["state"] == "OPEN"
    if mergeable == "UNKNOWN":   # polled with backoff up to ci_wait_min
        assert land_env.clock.monotonic() - start >= land_env.alpha.ci_wait_min * 60
        assert "unknown" in out.reason


@pytest.mark.parametrize("case", ["gate_input", "not_ancestor", "harmless"])
def test_base_not_ancestor_or_touching_gate_input_blocks_after_ci_wait(land_env, case):
    land_env.answer_gate_ask()
    if case == "gate_input":
        land_env.move_main({"tests/ci/test_new.py": "def test_x():\n    pass\n"})
    elif case == "not_ancestor":
        land_env.move_main({"README": "rewritten\n"}, rewrite=True)
    else:
        land_env.move_main({"docs/notes.md": "notes\n"})
    out = land_env.lander.land_consumer(land_env.alpha, land_env.rolled)
    if case == "harmless":   # BASE is an ancestor of D' and the diff touches no gate input
        assert out.state == "LANDED"
        return
    assert (out.state, out.step) == ("BLOCKED", "premerge") and "base moved" in out.reason
    assert ("tests/ci/test_new.py" if case == "gate_input" else "not an ancestor") in out.reason
    assert out.next_command == f"guard-fleet land {TAG} --rebuild alpha"
    assert [r.detail["verdict"] for r in land_env.records("ci")] == ["pass"]   # CI was waited for first
    assert land_env.pr(1)["state"] == "CLOSED" and merge_calls(land_env) == []


def test_quiet_before_merge_holds_then_blocks(land_env, fake_clock):
    alpha = dataclasses.replace(land_env.alpha, quiet_before_merge=("deploy.yml",))
    land_env.fake.runs[SLUG] = [{"databaseId": 5, "workflowFile": "deploy.yml", "workflowName": "Deploy",
                                 "headBranch": "main", "status": "in_progress", "conclusion": None, "headSha": "x"}]
    number, _, _ = land_env.lander.publish(alpha, land_env.rolled)
    start = fake_clock.monotonic()
    out = land_env.lander.premerge(alpha, land_env.rolled, number)
    assert out is not None and out.state == "BLOCKED" and "deploy queue busy" in out.reason
    assert out.keep_pr_open and out.next_command == f"guard-fleet land {TAG}"
    assert fake_clock.monotonic() - start >= alpha.ci_wait_min * 60
    assert len(land_env.gh_calls("gh", "run", "list")) > 2   # it held with backoff before giving up
    assert land_env.pr(number)["state"] == "OPEN"


def test_quiet_before_merge_waits_until_the_queue_drains(land_env, fake_clock):
    alpha = dataclasses.replace(land_env.alpha, quiet_before_merge=("deploy.yml",))
    run = {"databaseId": 5, "workflowFile": "deploy.yml", "headBranch": "main", "status": "queued", "headSha": "x"}
    land_env.fake.runs[SLUG] = [run]
    orig = land_env.fake._run_list
    seen = []

    def draining(argv, slug, env):
        seen.append(argv)
        if len(seen) == 2:
            run["status"] = "completed"
        return orig(argv, slug, env)
    land_env.fake._run_list = draining
    out = land_env.lander.land_consumer(alpha, land_env.rolled)
    assert out.state == "LANDED" and len(seen) == 3   # busy once, drained, then the premerge re-run's quiet poll
    assert land_env.count_calls("contents/guard.lock") == 2   # premerge ran again after the wait


def test_main_moving_into_a_gate_input_during_the_quiet_wait_blocks(land_env, fake_clock):
    land_env.answer_gate_ask()
    alpha = dataclasses.replace(land_env.alpha, quiet_before_merge=("deploy.yml",))
    run = {"databaseId": 5, "workflowFile": "deploy.yml", "headBranch": "main", "status": "queued", "headSha": "x"}
    land_env.fake.runs[SLUG] = [run]
    orig = land_env.fake._run_list
    seen = []

    def draining(argv, slug, env):   # main moves into a gate input while the deploy queue drains
        seen.append(argv)
        if len(seen) == 1:
            land_env.move_main({"tests/ci/test_new.py": "def test_x():\n    pass\n"})
        else:
            run["status"] = "completed"
        return orig(argv, slug, env)
    land_env.fake._run_list = draining
    out = land_env.lander.land_consumer(alpha, land_env.rolled)
    assert (out.state, out.step) == ("BLOCKED", "premerge") and "tests/ci/test_new.py" in out.reason
    assert merge_calls(land_env) == [] and land_env.pr(1)["state"] == "CLOSED"


def test_quiet_re_runs_are_bounded_and_share_one_wait_budget(land_env, fake_clock):
    alpha = dataclasses.replace(land_env.alpha, quiet_before_merge=("deploy.yml",))
    run = {"databaseId": 5, "workflowFile": "deploy.yml", "headBranch": "main", "status": "queued", "headSha": "x"}
    land_env.fake.runs[SLUG] = [run]
    orig = land_env.fake._run_list
    seen = []

    def flapping(argv, slug, env):   # every premerge sees one busy poll, then a drained one
        seen.append(argv)
        run["status"] = "queued" if len(seen) % 2 else "completed"
        return orig(argv, slug, env)
    land_env.fake._run_list = flapping
    start = fake_clock.monotonic()
    out = land_env.lander.land_consumer(alpha, land_env.rolled)
    assert (out.state, out.step) == ("BLOCKED", "premerge") and "re-runs" in out.reason
    assert out.keep_pr_open and out.next_command == f"guard-fleet land {TAG}"
    assert land_env.count_calls("contents/guard.lock") == 1 + land_mod.PREMERGE_RERUNS
    assert merge_calls(land_env) == [] and land_env.pr(1)["state"] == "OPEN"
    assert fake_clock.monotonic() - start <= alpha.ci_wait_min * 60 + 60


def test_ci_verdict_other_than_pass_fails_closed(land_env, monkeypatch):
    monkeypatch.setattr(land_mod, "wait_for_ci", lambda *a, **k: ("pending", []))
    out = land_env.lander.land_consumer(land_env.alpha, land_env.rolled)
    assert (out.state, out.step) == ("BLOCKED", "ci") and "pending" in out.reason and out.keep_pr_open
    assert merge_calls(land_env) == []


@pytest.mark.parametrize("network", [False, True])
def test_a_git_error_in_the_base_moved_diff_blocks_network_loss_propagates(land_env, monkeypatch, network):
    land_env.move_main({"docs/notes.md": "notes\n"})
    err = (GitNetworkError if network else GitError)(Result(("git", "diff"), 128, b"", b"fatal: bad", False))

    def boom(*a, **k):
        raise err
    monkeypatch.setattr(land_env.lander, "_gate_hits", boom)
    if network:
        with pytest.raises(GitNetworkError):
            land_env.lander.land_consumer(land_env.alpha, land_env.rolled)
        return
    out = land_env.lander.land_consumer(land_env.alpha, land_env.rolled)
    assert (out.state, out.step) == ("BLOCKED", "premerge") and "cannot diff" in out.reason
    assert merge_calls(land_env) == []


# -- merge and the read-back ---------------------------------------------------------------------------------


@pytest.mark.parametrize("state,expected", [("MERGED_AT_H", "LANDED"), ("MERGED_ELSEWHERE", "FAILED"),
                                            ("OPEN", "BLOCKED")])
def test_merge_result_always_read_back(land_env, monkeypatch, state, expected):
    def effect(orig, argv, slug, env):
        if state != "OPEN":
            orig(argv, slug, env)
        if state == "MERGED_ELSEWHERE":
            land_env.pr(int(argv[3]))["headRefOid"] = "e" * 40
        return Result(argv, 1, b"", b"gh: something odd", False)   # merge rc 1 in every case
    land_env.patch_merge(monkeypatch, effect)
    out = land_env.lander.land_consumer(land_env.alpha, land_env.rolled)
    assert out.state == expected
    views = [a for a in land_env.gh_calls("gh", "pr", "view") if "state,mergeCommit,headRefOid" in a]
    assert views   # read back whatever the exit code
    if expected == "BLOCKED":
        assert out.step == "merge" and "OPEN" in out.reason and out.keep_pr_open
    if expected == "FAILED":
        assert out.step == "merge" and out.merge_sha == sha_of(land_env.bare, "main")
        assert [r.detail["verdict"] for r in land_env.records("merge")] == ["fail"]


@pytest.mark.parametrize("fn", ["fetch_default", "rev_parse"])
@pytest.mark.parametrize("exc", [GitError, GitNetworkError])
def test_a_git_error_in_the_post_merge_read_back_is_failed_not_an_escape(land_env, monkeypatch, fn, exc):
    err = exc(Result(("git", "fetch"), 128, b"", b"fatal: unreachable", False))

    def effect(orig, argv, slug, env):
        res = orig(argv, slug, env)   # the merge really happens; only the local read-back breaks

        def boom(*a, **k):
            raise err
        monkeypatch.setattr(land_mod, fn, boom)
        return res
    land_env.patch_merge(monkeypatch, effect)
    out = land_env.lander.land_consumer(land_env.alpha, land_env.rolled)
    merged = sha_of(land_env.bare, "main")
    assert (out.state, out.step, out.merge_sha) == ("FAILED", "merge", merged)   # FAILED -> run exit 6 (release.py)
    assert out.reason == f"merge: PR #1 merged as {merged[:12]} but the read-back failed: {err}"
    recs = land_env.records("merge")
    assert [(r.detail["verdict"], r.detail["merge"]) for r in recs] == [("fail", merged)]
    assert recs[0].detail["reason"] == out.reason


def test_network_loss_during_the_read_back_propagates(land_env, monkeypatch):
    def effect(orig, argv, slug, env):
        orig(argv, slug, env)
        land_env.ctx.deps.run.routes.insert(0, Route(match=lambda a: a[:3] == ("gh", "pr", "view"), rc=1,
                                                     stderr=b"error connecting to api.github.com"))
        return Result(argv, 0, b"", b"", False)
    land_env.patch_merge(monkeypatch, effect)
    with pytest.raises(GhNetworkError):
        land_env.lander.land_consumer(land_env.alpha, land_env.rolled)


def test_post_merge_gate_input_change_is_failed_exit_6(land_env, monkeypatch):
    land_env.answer_gate_ask()

    def effect(orig, argv, slug, env):   # the base moves into a gate input after premerge, before the merge
        land_env.move_main({"tests/ci/test_late.py": "def test_late():\n    pass\n"})
        return orig(argv, slug, env)
    land_env.patch_merge(monkeypatch, effect)
    out = land_env.lander.land_consumer(land_env.alpha, land_env.rolled)
    assert (out.state, out.step) == ("FAILED", "verify")
    assert "tests/ci/test_late.py" in out.reason and out.merge_sha == sha_of(land_env.bare, "main")
    assert [r.detail["verdict"] for r in land_env.records("verify")] == ["fail"]
    assert out.cleanup == ()   # no cleanup after a failed verify


def test_verify_checks_lock_and_shim_at_the_new_default_head(land_env):
    out = land_env.lander.land_consumer(land_env.alpha, land_env.rolled)
    assert out.state == "LANDED"
    land_env.move_main({"guard.lock": render_lock(land_env.p, "php")})   # someone reverted the lock on main
    before = len(land_env.calls)
    again = land_env.lander.verify(land_env.alpha, land_env.rolled, out.merge_sha)
    assert again.state == "FAILED" and "guard.lock at main" in again.reason
    order = [("ls-remote" if "ls-remote" in a else "fetch") for a, _, _ in land_env.calls[before:]
             if a[:1] == ("git",) and ("ls-remote" in a or "fetch" in a)]
    assert order[:2] == ["ls-remote", "fetch"]   # D first, then its objects (as _base_moved does)


@pytest.mark.parametrize("network", [False, True])
def test_a_git_error_in_verify_fails_network_loss_propagates_unrecorded(land_env, monkeypatch, network):
    out = land_env.lander.land_consumer(land_env.alpha, land_env.rolled)
    assert out.state == "LANDED"
    before = [r.detail["verdict"] for r in land_env.records("verify")]
    err = (GitNetworkError if network else GitError)(Result(("git", "diff"), 128, b"", b"fatal: bad", False))

    def boom(*a, **k):
        raise err
    monkeypatch.setattr(land_env.lander, "_gate_hits", boom)
    if network:
        with pytest.raises(GitNetworkError):
            land_env.lander.verify(land_env.alpha, land_env.rolled, out.merge_sha)
        assert [r.detail["verdict"] for r in land_env.records("verify")] == before   # nothing recorded
        return
    again = land_env.lander.verify(land_env.alpha, land_env.rolled, out.merge_sha)
    assert (again.state, again.step) == ("FAILED", "verify") and "fatal: bad" in again.reason
    assert [r.detail["verdict"] for r in land_env.records("verify")] == [*before, "fail"]


# -- the push-run gate -----------------------------------------------------------------------------------------


def _seed_push_run(env, merge, governance="success", other="failure"):
    env.fake.runs[SLUG] = [{"databaseId": 9, "headSha": merge, "event": "push", "workflowName": "CI",
                            "status": "completed", "conclusion": "failure"}]
    env.fake.jobs[1] = {"id": 1, "run_id": 9, "name": GOVERNANCE_JOB, "status": "completed",
                        "conclusion": governance}
    env.fake.jobs[2] = {"id": 2, "run_id": 9, "name": "tests (windows-latest, 3.13)", "status": "completed",
                        "conclusion": other}


def test_push_run_gate_fails_on_governance_job_only(land_env):
    out = land_env.lander.land_consumer(land_env.alpha, land_env.rolled)
    assert out.state == "LANDED"
    _seed_push_run(land_env, out.merge_sha)
    assert land_env.lander.push_run_gate(land_env.alpha, out.merge_sha) is None
    assert "tests (windows-latest, 3.13)" in land_env.ctx.deps.out.getvalue()   # reported only
    land_env.fake.jobs[1]["conclusion"] = "failure"
    failed = land_env.lander.push_run_gate(land_env.alpha, out.merge_sha)
    assert failed is not None and (failed.state, failed.step) == ("FAILED", "push-run")
    assert GOVERNANCE_JOB in failed.reason
    recs = land_env.records("push-run")
    assert [r.detail["verdict"] for r in recs] == ["pass", "fail"] and recs[0].head == land_env.rolled.head


def test_push_run_gate_no_run_in_time_is_failed(land_env, fake_clock):
    out = land_env.lander.land_consumer(land_env.alpha, land_env.rolled)
    start = fake_clock.monotonic()
    failed = land_env.lander.push_run_gate(land_env.alpha, out.merge_sha)
    assert failed is not None and failed.state == "FAILED" and "within" in failed.reason
    assert fake_clock.monotonic() - start >= land_env.alpha.ci_wait_min * 60


def test_push_run_gate_waits_for_an_in_progress_governance_job(land_env, fake_clock):
    out = land_env.lander.land_consumer(land_env.alpha, land_env.rolled)
    _seed_push_run(land_env, out.merge_sha, other="success")
    land_env.fake.jobs[1].update(status="in_progress", conclusion=None)
    orig = land_env.fake._run_list
    polls = []

    def finishing(argv, slug, env):
        polls.append(argv)
        if len(polls) == 3:
            land_env.fake.jobs[1].update(status="completed", conclusion="success")
        return orig(argv, slug, env)
    land_env.fake._run_list = finishing
    assert land_env.lander.push_run_gate(land_env.alpha, out.merge_sha) is None and len(polls) == 3


def test_deploy_report_is_read_only(land_env):
    alpha = dataclasses.replace(land_env.alpha, deploy_workflows=("deploy.yml", "gone.yml"))
    land_env.fake.workflows[(SLUG, "deploy.yml")] = "active"
    land_env.fake.runs[SLUG] = [{"databaseId": 3, "headSha": "m" * 40, "event": "push", "workflowFile": "deploy.yml",
                                 "status": "queued", "conclusion": None}]
    before = len(land_env.calls)
    lines = land_env.lander.deploy_report(alpha, "m" * 40)
    assert lines == [f"alpha: deploy deploy.yml: active; runs for {'m' * 12}: #3 push queued",
                     f"alpha: deploy gone.yml: not found; runs for {'m' * 12}: none"]
    new = [a for a, _, _ in land_env.calls[before:]]
    assert all(a[:3] in (("gh", "api", "-i"), ("gh", "run", "list")) and "-X" not in a for a in new)


# -- publish: PRs ------------------------------------------------------------------------------------------------


def _pr(number, branch, *, cross=False, login=LOGIN):
    return {"number": number, "url": f"https://github.com/{SLUG}/pull/{number}", "state": "OPEN",
            "headRefName": branch, "baseRefName": "main", "headRefOid": "d" * 40, "isCrossRepository": cross,
            "author": {"login": login}}


def test_superseded_fleet_pr_closed_with_comment_and_fork_pr_untouched(land_env):
    land_env.fake.prs[SLUG] = [_pr(1, "chore/agent-ratchet-4.0.0"),
                               _pr(2, "chore/agent-ratchet-4.0.0", cross=True),
                               _pr(3, "chore/agent-ratchet-4.0.2"),
                               _pr(4, "feature/other"),
                               _pr(5, "chore/agent-ratchet-3.9.9", login="someone")]
    number, url, _ = land_env.lander.publish(land_env.alpha, land_env.rolled)
    assert number == 6
    assert land_env.fake.closed_comments == {(SLUG, 1): f"superseded by {url}"}
    assert [land_env.pr(n)["state"] for n in (2, 3, 4, 5, 6)] == ["OPEN"] * 5


def test_existing_pr_at_h_is_reused_other_open_pr_blocks(land_env):
    first = land_env.lander.publish(land_env.alpha, land_env.rolled)
    second = land_env.lander.publish(land_env.alpha, land_env.rolled)
    assert first[:2] == second[:2] and len(land_env.gh_calls("gh", "pr", "create")) == 1
    pushes = [a for a, _, _ in land_env.calls if a[:1] == ("git",) and "push" in a]
    assert len(pushes) == 1   # the remote branch at H is reused
    land_env.fake.prs[SLUG].append(_pr(2, land_env.branch, cross=True))   # a fork PR from a same-named branch
    out = land_env.lander.publish(land_env.alpha, land_env.rolled)
    assert out.state == "BLOCKED" and "another open PR" in out.reason
    land_env.fake.prs[SLUG] = [dict(_pr(1, land_env.branch), headRefOid="e" * 40)]   # ours, but at another head
    assert land_env.lander.publish(land_env.alpha, land_env.rolled).state == "BLOCKED"


@pytest.mark.parametrize("remote,flag,landed", [("recorded", True, True), ("recorded", False, False),
                                                ("foreign", True, False)])
def test_rebuild_lease_only_on_recorded_head(land_env, remote, flag, landed):
    h = land_env.rolled.head
    if remote == "recorded":
        old = _git(land_env.clone, "rev-parse", f"{h}^")   # C1: the ledger recorded it as a head
        assert old in land_env.ctx.ledger.heads_recorded("alpha")
    else:   # someone else's commit on the fleet branch name
        work = land_env.other_clone()
        old = commit_files(work, "foreign", {"README": "foreign\n"})
    _git(land_env.clone if remote == "recorded" else work, "push", "-q", "origin", f"{old}:refs/heads/{land_env.branch}")
    lander = land_env.make_lander(flags=frozenset({f"{REBUILD_FLAG}alpha"} if flag else set()))
    got = lander.publish(land_env.alpha, land_env.rolled)
    pushes = [a for a, _, _ in land_env.calls
              if a[:1] == ("git",) and "push" in a and any(x.startswith("--force-with-lease") for x in a)]
    if landed:
        assert isinstance(got, tuple) and sha_of(land_env.bare, land_env.branch) == h
        assert any(f"--force-with-lease=refs/heads/{land_env.branch}:{old}" in a for a in pushes)
    elif flag:   # --rebuild was given and refused: never suggest it again
        assert got.state == "BLOCKED" and got.next_command is None
        assert "inspect owner/alpha" in got.reason and "--rebuild will not replace it" in got.reason
        assert pushes == [] and sha_of(land_env.bare, land_env.branch) == old
    else:
        assert got.state == "BLOCKED" and got.next_command == f"guard-fleet land {TAG} --rebuild alpha"
        assert pushes == [] and sha_of(land_env.bare, land_env.branch) == old


def test_rebuild_remote_ok_accepts_a_strict_fleet_bump_not_in_the_ledger(land_env, tmp_path):
    """A remote B holding only the fleet's bump, rolled elsewhere, passes strict G8 and may be replaced."""
    work = land_env.other_clone("elsewhere")
    _git(work, "fetch", "-q", str(land_env.clone), f"refs/heads/{land_env.branch}:refs/heads/elsewhere")
    _git(work, "checkout", "-q", "elsewhere")
    _git(work, "commit", "-q", "--amend", "-m", f"chore(guard): bump agent-ratchet to v4.0.1 ({land_env.t})",
         "--date", "2001-01-01T00:00:00")
    other = sha_of(work, "HEAD")
    assert other != land_env.rolled.head and other not in land_env.ctx.ledger.heads_recorded("alpha")
    _git(work, "push", "-q", "origin", f"{other}:refs/heads/{land_env.branch}")
    assert land_env.lander.rebuild_remote_ok(land_env.alpha, other) is True
    commits = land_env.lander.rebuild_remote_commits(land_env.alpha, other)
    pin = _git(work, "rev-parse", "HEAD^")   # C1 pin, then C2 bump: oldest first
    assert commits == [f"{pin} build(deps): pin agent-ratchet v4.0.1 in dev dependencies",
                       f"{other} chore(guard): bump agent-ratchet to v4.0.1 ({land_env.t})"]


def test_rebuild_remote_commits_empty_for_a_recorded_head_none_for_a_foreign_one(land_env):
    h = land_env.rolled.head
    recorded = _git(land_env.clone, "rev-parse", f"{h}^")
    assert land_env.lander.rebuild_remote_commits(land_env.alpha, recorded) == []
    work = land_env.other_clone()
    foreign = commit_files(work, "foreign", {"README": "foreign\n"})
    _git(work, "push", "-q", "origin", f"{foreign}:refs/heads/{land_env.branch}")
    assert land_env.lander.rebuild_remote_commits(land_env.alpha, foreign) is None
    assert land_env.lander.rebuild_remote_ok(land_env.alpha, foreign) is False


# -- approval, clocks ------------------------------------------------------------------------------------------


@pytest.mark.parametrize("gap,expected", [(0, 1), (300, 2)])
def test_wall_clock_gap_reruns_premerge(land_env, fake_clock, gap, expected):
    fake_clock.advance(gap, wall_only=True)
    out = land_env.lander.land_consumer(land_env.alpha, land_env.rolled)
    assert out.state == "LANDED"
    assert land_env.count_calls("contents/guard.lock") == expected


@pytest.mark.parametrize("heads,t", [({}, None), ({"alpha": "e" * 40}, None), (None, "a" * 40)])
def test_not_in_approval_blocks(land_env, heads, t):
    lander = land_env.make_lander(heads=heads, t=t)
    before = len(land_env.calls)
    out = lander.land_consumer(land_env.alpha, land_env.rolled)
    assert (out.state, out.step, out.reason) == ("BLOCKED", "approval", "not in approval")
    assert land_env.calls[before:] == []   # nothing pushed, nothing asked


def test_approval_covers_only_its_heads_and_peel():
    a = Approval(TAG, "t" * 40, {"alpha": "h" * 40}, frozenset())
    assert a.covers("alpha", "h" * 40, "t" * 40)
    assert not a.covers("alpha", "x" * 40, "t" * 40) and not a.covers("beta", "h" * 40, "t" * 40)
    assert not a.covers("alpha", "h" * 40, "x" * 40)


# -- re-verify and rebuild ---------------------------------------------------------------------------------------


def test_reverify_current_reads_the_merged_fleet_pr(land_env):
    out = land_env.lander.land_consumer(land_env.alpha, land_env.rolled)
    assert out.state == "LANDED"
    again = land_env.lander.reverify_current(land_env.alpha, canary=False)
    assert (again.state, again.merge_sha, again.pr_url) == ("LANDED", out.merge_sha, out.pr_url)
    argv = [a for a in land_env.gh_calls("gh", "pr", "list") if "merged" in a]
    assert argv and argv[-1][argv[-1].index("--state") + 1] == "merged"
    failed = land_env.lander.reverify_current(land_env.alpha, canary=True)   # no push run: the canary FAILs
    assert (failed.state, failed.step) == ("FAILED", "push-run")
    _seed_push_run(land_env, out.merge_sha)
    assert land_env.lander.reverify_current(land_env.alpha, canary=True).state == "LANDED"


def test_reverify_current_without_a_merged_pr_blocks(land_env):
    out = land_env.lander.reverify_current(land_env.alpha, canary=False)
    assert (out.state, out.step) == ("BLOCKED", "verify")


def test_merged_verified_reads_and_verifies_without_mutating_anything(land_env):
    out = land_env.lander.land_consumer(land_env.alpha, land_env.rolled)
    assert out.state == "LANDED"
    # land's cleanup removed B; put the remote branch back so a stray cleanup would have something to delete
    _git(land_env.bare, "branch", land_env.branch, land_env.rolled.head)
    before = len(land_env.calls)
    again = land_env.lander.merged_verified(land_env.alpha)
    assert (again.state, again.step, again.merge_sha, again.pr_url) == ("LANDED", "verify", out.merge_sha,
                                                                       out.pr_url)
    assert again.cleanup == () and not again.cleanup_kept
    assert _git(land_env.bare, "branch", "--list", land_env.branch) != ""   # cleanup did not run
    new = [a for a, _, _ in land_env.calls[before:]]
    assert not [a for a in new if a[:1] == ("gh",) and (a[1:3] in (("pr", "merge"), ("pr", "close"), ("pr", "create"))
                                                        or "-X" in a)]
    assert not [a for a in new if a[:1] == ("git",) and any(w in a for w in ("push", "branch", "worktree"))]
    assert [r.detail["verdict"] for r in land_env.records("verify")] == ["pass", "pass"]


def test_merged_verified_failed_when_the_default_head_lost_the_lock(land_env):
    out = land_env.lander.land_consumer(land_env.alpha, land_env.rolled)
    assert out.state == "LANDED"
    land_env.move_main({"guard.lock": "tampered\n"})
    failed = land_env.lander.merged_verified(land_env.alpha)
    assert (failed.state, failed.step) == ("FAILED", "verify") and failed.merge_sha == out.merge_sha


def test_merged_verified_without_a_merged_pr_blocks(land_env):
    out = land_env.lander.merged_verified(land_env.alpha)
    assert (out.state, out.step) == ("BLOCKED", "verify") and out.merge_sha is None


def test_rebuild_local_removes_the_fleet_worktree_and_branch(land_env):
    (land_env.wt / "guard.lock").write_bytes((land_env.wt / "guard.lock").read_bytes())   # same bytes: fine
    land_env.lander.rebuild_local(land_env.alpha)
    assert not land_env.wt.exists()
    assert _git(land_env.clone, "branch", "--list", land_env.branch) == ""
    removes = [a for a, _, _ in land_env.calls if a[:1] == ("git",) and "remove" in a]
    assert removes and all("--force" not in a for a in removes)


@pytest.mark.parametrize("dirt", ["foreign_file", "foreign_commit"])
def test_rebuild_local_blocks_on_anything_not_the_fleets(land_env, dirt):
    if dirt == "foreign_file":
        (land_env.wt / "notes.txt").write_text("mine\n")
    else:
        commit_files(land_env.wt, "my own change", {"README": "edited\n"})
    with pytest.raises(RebuildBlocked):
        land_env.lander.rebuild_local(land_env.alpha)
    assert land_env.wt.is_dir() and _git(land_env.clone, "branch", "--list", land_env.branch) != ""


def _exclude(env, *patterns):
    info = env.clone / ".git" / "info"
    info.mkdir(exist_ok=True)
    (info / "exclude").write_text("".join(f"{p}\n" for p in patterns))


def test_rebuild_local_blocks_on_an_ignored_file_outside_the_allowlist(land_env):
    _exclude(land_env, "*.log", "__pycache__/")
    (land_env.wt / "__pycache__").mkdir()
    (land_env.wt / "__pycache__" / "x.pyc").write_bytes(b"\0")
    (land_env.wt / "debug.log").write_text("keep me\n")
    with pytest.raises(RebuildBlocked, match="debug.log"):
        land_env.lander.rebuild_local(land_env.alpha)
    assert (land_env.wt / "debug.log").read_text() == "keep me\n"
    (land_env.wt / "debug.log").unlink()   # only allowlisted ignored files left: the rebuild goes ahead
    land_env.lander.rebuild_local(land_env.alpha)
    assert not land_env.wt.exists()


def test_rebuild_local_mutates_nothing_before_it_blocks(land_env):
    (land_env.clone / "node_modules").mkdir()
    link = land_env.wt / "node_modules"
    link.symlink_to(land_env.clone / "node_modules")
    lock = land_env.wt / "guard.lock"
    lock.chmod(0o755)   # a fleet path whose restore would reset the mode
    (land_env.wt / "zz-notes.txt").write_text("mine\n")   # sorts after guard.lock
    with pytest.raises(RebuildBlocked, match="zz-notes.txt"):
        land_env.lander.rebuild_local(land_env.alpha)
    assert link.is_symlink() and lock.stat().st_mode & 0o777 == 0o755
    restores = [a for a, _, _ in land_env.calls if a[:1] == ("git",) and "restore" in a]
    assert restores == []
