"""`release` and `land` end to end: real git on bare repositories, FakeGh for GitHub, FakeConfirm for Touch ID.

`ReleaseEnv` builds upstream tags v4.0.0 and v4.0.1 (the shim changes, so every consumer plans BUMP) and three
consumers pinned to v4.0.0: alpha (ring 1, req pin), the canary beta (ring 1, ci = required, pyproject pin) and
gamma (ring 2, no pin). The running fleet is v4.0.0.
"""

import os

import pytest

from fakes import FakeConfirm, FakeGh, Route, make_deps
from guard_fleet import gh as gh_mod
from guard_fleet.config import load_config
from guard_fleet.env import base_child_env
from guard_fleet.exits import FleetExit, UsageError
from guard_fleet.gh import GhNetworkError
from guard_fleet.land import GOVERNANCE_JOB
from guard_fleet.lockfile import render_lock
from guard_fleet.locks import RunLock
from guard_fleet.mirror import UPSTREAM_URL
from guard_fleet.names import branch_for
from guard_fleet.release import Options, run_land, run_release
from guard_fleet.selfcheck import SelfCheckError
from repos import _git, commit_files, make_bare, make_clone, make_upstream, push_all, redirect, sha_of
from test_roll import KINDS, NEW_SHIM, OLD_SHIM, PIN_TEST_TEXT, TAG, gate_routes, pin_text, uv_lock_text

RINGS = {"alpha": (1, "if-run"), "beta": (1, "required"), "gamma": (2, "if-run")}
BRANCH = branch_for("4.0.1")
C2_PREFIX = "chore(guard): bump agent-ratchet to v4.0.1 ("
RESUME = f"guard-fleet land {TAG}"


class ReleaseEnv:
    def __init__(self, tmp_path, home, *, locks=None):
        self.tmp, self.home = tmp_path, home
        up = make_upstream(tmp_path / "up", {"v4.0.0": {"consumer/guard": OLD_SHIM},
                                             TAG: {"consumer/guard": NEW_SHIM}})
        redirect(home, UPSTREAM_URL, up)
        self.up, self.p, self.t = up, sha_of(up, "v4.0.0"), sha_of(up, TAG)
        self.bares, self.clones = {}, {}
        toml = [f'worktree_root = "{tmp_path}/wt"\n']
        for name in ("alpha", "beta", "gamma"):   # file order; ring order puts the canary beta first
            kind, pin_file, extras = KINDS[name]
            ring, ci = RINGS[name]
            bare = make_bare(tmp_path / "gh", name)
            clone = make_clone(bare, tmp_path / "repos" / name)
            files = {"README": "x\n", "guard.lock": (locks or {}).get(name, render_lock(self.p, extras))}
            if pin_file:
                files[pin_file] = pin_text(name, self.p)
                files["tests/ci/test_guard_pin.py"] = PIN_TEST_TEXT
            if kind == "pyproject":
                files["uv.lock"] = uv_lock_text(self.p)
            commit_files(clone, "init", files)
            commit_files(clone, "shim", {"scripts/guard": OLD_SHIM}, mode="755")
            push_all(clone)
            url = f"https://github.com/owner/{name}"
            _git(clone, "remote", "set-url", "origin", url)
            redirect(home, url, bare)
            self.bares[f"owner/{name}"], self.clones[name] = bare, clone
            toml += ["[[consumer]]", f'short = "{name}"', f'dir = "{clone}"', f'slug = "owner/{name}"',
                     'default_branch = "main"', f'pin_kind = "{kind}"', f"ring = {ring}", f'ci = "{ci}"']
            if pin_file:
                toml.append(f'pin_file = "{pin_file}"')
        cfg_path = home / ".config" / "guard-fleet" / "consumers.toml"
        cfg_path.parent.mkdir(parents=True, exist_ok=True)
        cfg_path.write_text("\n".join(toml) + "\n", encoding="utf-8")
        self.cfg = load_config(cfg_path, home=home)

        fakebin = tmp_path / "bin"
        fakebin.mkdir()
        for tool in ("uv", "uvx", "python3"):
            (fakebin / tool).write_text("#!/bin/sh\nexit 0\n")
            (fakebin / tool).chmod(0o755)
        environ = base_child_env(os.environ, tool_bin=tmp_path / "no-tool-bin")
        environ["HOME"] = str(home)
        environ["PATH"] = os.pathsep.join((str(fakebin), "/usr/bin", "/bin"))

        def fake_uv_lock(argv, cwd, env):
            lock = cwd / "uv.lock"
            lock.write_text(lock.read_text().replace(self.p, self.t))

        self.fake = FakeGh(self.bares)
        self._green_checks_on_canary_prs()
        self._push_runs_for_canary_merges()
        self.confirm = FakeConfirm(["approved"] * 4)
        self.deps = make_deps(home, routes=[self.fake.route(), Route(match=("pgrep", "-f", "guard_bump.sh"), rc=1),
                                            Route(match=("uv", "lock"), effect=fake_uv_lock), *gate_routes(self.t)],
                              confirm=lambda reason: self.confirm(reason), environ=environ)
        self.calls = self.deps.run.calls
        self.running_sha = self.p
        self.typed = f"guard-fleet release {TAG}"

    # -- GitHub-side behaviour of the canary -----------------------------------

    def _green_checks_on_canary_prs(self):
        orig = self.fake._pr_create

        def create(argv, slug, env):
            res = orig(argv, slug, env)
            if slug == "owner/beta":
                self.fake.prs[slug][-1]["statusCheckRollup"] = [
                    {"__typename": "CheckRun", "name": "CI", "status": "COMPLETED", "conclusion": "SUCCESS",
                     "startedAt": "2026-01-01T00:00:00Z"}]
            return res
        self.fake._pr_create = create

    def _push_runs_for_canary_merges(self):
        orig = self.fake._run_list
        self.push_run_conclusion = "success"

        def run_list(argv, slug, env):
            merged = [p for p in self.fake.prs.get("owner/beta", []) if p.get("state") == "MERGED"]
            if slug == "owner/beta" and "--event" in argv and merged and self.push_run_conclusion:
                merge = merged[-1]["mergeCommit"]["oid"]
                self.fake.runs[slug] = [{"databaseId": 9, "headSha": merge, "event": "push", "workflowName": "CI",
                                         "status": "completed", "conclusion": "success"}]
                self.fake.jobs[1] = {"id": 1, "run_id": 9, "name": GOVERNANCE_JOB, "status": "completed",
                                     "conclusion": self.push_run_conclusion}
            return orig(argv, slug, env)
        self.fake._run_list = run_list

    # -- driving ---------------------------------------------------------------

    def opts(self, **kw):
        base = dict(tag=TAG, only=(), include_unexposed=False, rebuild=(), diff=False, hold_ring_2=False, rings=())
        return Options(**{**base, **kw})

    @property
    def args(self):
        return self.deps, self.cfg, self.opts()

    def release(self, *, lock_update=True, running_sha=None, **kw):
        return run_release(self.deps, self.cfg, self.opts(**kw), lock_update=lock_update,
                           running_sha=running_sha or self.running_sha, typed=self.typed)

    def land(self, *, lock_update=False, **kw):
        typed = f"guard-fleet land {TAG}" + "".join(f" --rebuild {s}" for s in kw.get("rebuild", ()))
        return run_land(self.deps, self.cfg, self.opts(**kw), lock_update=lock_update,
                        running_sha=self.running_sha, typed=typed)

    # -- reading results -------------------------------------------------------

    def out(self):
        return self.deps.out.getvalue()

    def merged(self):
        """Consumers in the order their fleet PR was merged."""
        order = []
        for argv in self.fake.argvs:
            if argv[1:3] == ("pr", "merge"):
                slug = argv[argv.index("--repo") + 1]
                pr = next(p for p in self.fake.prs[slug] if p["number"] == int(argv[3]))
                if pr["state"] == "MERGED" and slug.split("/")[1] not in order:
                    order.append(slug.split("/")[1])
        return order

    def remote_side_effects(self):
        pushes = [a for a, _, _ in self.calls if a[:1] == ("git",) and "push" in a]
        gh_writes = [a for a in self.fake.argvs if a[1:3] in (("pr", "create"), ("pr", "merge"), ("pr", "close"))]
        return pushes + gh_writes

    def is_c2(self, argv):
        return "-m" in argv and argv[argv.index("-m") + 1].startswith(C2_PREFIX)

    def remote_branch(self, short):
        return _git(self.bares[f"owner/{short}"], "branch", "--list", BRANCH)

    def end(self):
        """The end-of-run table of the latest run: short -> state text."""
        out = self.out()
        rows = out[out.rindex("CONSUMER  STATE"):].split("\n\n")[0].splitlines()[1:]
        return dict(line.split(None, 1) for line in rows)

    def records(self, short, step):
        from guard_fleet.ledger import Ledger
        return [r for r in Ledger(self.deps.dirs.ledger(TAG), self.deps.clock).records()[0]
                if r.consumer == short and r.step == step]


@pytest.fixture
def release_env(tmp_path, fleet_home):
    return ReleaseEnv(tmp_path, fleet_home)


# -- the env var and the refusals ------------------------------------------------------------------------------


def test_release_without_env_var_refuses_and_names_command(release_env, capsys):
    assert release_env.release(lock_update=False) is FleetExit.USAGE
    out = release_env.out()
    assert "Run: ALLOW_GUARD_LOCK_UPDATE=1 guard-fleet release v4.0.1" in out
    assert release_env.confirm.reasons == [] and release_env.fake.argvs == []   # refused before any GitHub call
    assert not [a for a, _, _ in release_env.calls if a[:1] == ("git",) and "commit" in a]


def test_release_with_markers_prints_no_ready_line(release_env):
    release_env.deps.environ["CLAUDECODE"] = "1"
    assert release_env.release(lock_update=False) is FleetExit.USAGE
    out = release_env.out()
    assert "Run in your own terminal: guard-fleet release v4.0.1" in out
    assert "ALLOW_GUARD_LOCK_UPDATE=1 set by you" in out
    assert "ALLOW_GUARD_LOCK_UPDATE=1 guard-fleet" not in out and "Run: " not in out


def test_running_sha_equal_to_target_refused(release_env):
    with pytest.raises(SelfCheckError, match="equals the target"):
        release_env.release(running_sha=release_env.t)
    assert release_env.remote_side_effects() == [] and release_env.confirm.reasons == []
    assert RunLock(release_env.deps.dirs.run_lock).acquire(exclusive=True)


def test_guard_bump_running_refused(release_env):
    release_env.deps.run.routes.insert(0, Route(match=("pgrep", "-f", "guard_bump.sh"), rc=0))
    with pytest.raises(UsageError, match="guard_bump.sh is running"):
        release_env.release()
    assert release_env.fake.argvs == [] and release_env.confirm.reasons == []
    with pytest.raises(UsageError, match="guard_bump.sh is running"):
        release_env.land()


def test_busy_lock_is_a_usage_error(release_env):
    held = RunLock(release_env.deps.dirs.run_lock)
    assert held.acquire(exclusive=False)
    try:
        with pytest.raises(UsageError, match="lock busy"):
            release_env.release()
    finally:
        held.release()


def test_unknown_or_unrolled_rebuild_short_is_a_usage_error(release_env):
    with pytest.raises(UsageError, match="unknown consumer 'delta'"):
        release_env.release(rebuild=("delta",))
    with pytest.raises(UsageError, match="--rebuild alpha"):
        release_env.release(only=("beta",), rebuild=("alpha",))   # not part of this run
    assert release_env.remote_side_effects() == []


# -- the happy path and the confirmation -----------------------------------------------------------------------


def test_release_happy_path_one_confirmation_lands_both_rings(release_env):
    assert release_env.release() is FleetExit.OK
    assert len(release_env.confirm.reasons) == 1 and release_env.merged() == ["beta", "alpha", "gamma"]
    reason = release_env.confirm.reasons[0]
    assert reason == f"release {TAG} ({release_env.t[:7]}): ring 1 beta, alpha; ring 2 gamma"
    out = release_env.out()
    assert f"Release {TAG}: T {release_env.t}" in out                  # the confirmation table came first
    assert out.index("PRs to open:") < out.index("CONSUMER  STATE")    # ... and the end table last
    for short in ("alpha", "beta", "gamma"):
        assert f"{short}: chore(guard): bump agent-ratchet to v4.0.1" in out
        assert release_env.remote_branch(short) == ""                  # cleaned up under the approval
    assert release_env.end() == {"alpha": "LANDED", "beta": "LANDED", "gamma": "LANDED"}
    body = (release_env.deps.dirs.consumer_dir(TAG, "alpha") / "pr-body.md").read_text()
    assert f"Opened by guard-fleet v4.0.0 ({release_env.p[:8]})." in body   # the real running tag and sha


def test_no_merge_without_approval(release_env):
    release_env.confirm = FakeConfirm(["cancelled"])
    assert release_env.release() is FleetExit.CANCELLED
    assert release_env.remote_side_effects() == [] and release_env.merged() == []
    assert len(release_env.confirm.reasons) == 1
    assert "detail-cancelled" in release_env.deps.err.getvalue()


def test_no_helper_exits_5_before_any_push(release_env):
    release_env.confirm = FakeConfirm(["no_helper"])
    assert release_env.release() is FleetExit.NO_HELPER
    assert release_env.remote_side_effects() == []
    assert "detail-no_helper" in release_env.deps.err.getvalue()


def test_confirmation_timeout_exits_4_and_releases_lock(release_env):
    release_env.confirm = FakeConfirm(["timeout"])
    assert release_env.release() is FleetExit.CANCELLED
    assert release_env.remote_side_effects() == []
    lock = RunLock(release_env.deps.dirs.run_lock)
    assert lock.acquire(exclusive=True)
    lock.release()


def test_only_leaves_the_others_not_run_and_the_canary_blocks_ring_1(release_env):
    assert release_env.release(only=("alpha",)) is FleetExit.BLOCKED
    assert release_env.merged() == []
    end = release_env.end()
    assert end["beta"] == end["gamma"] == "NOT RUN"
    assert end["alpha"].startswith("BLOCKED canary: ") and "--only" in end["alpha"]


# -- hold, land and resume -------------------------------------------------------------------------------------


def test_hold_ring_2_exit_0_then_land_ring_2(release_env):
    assert release_env.release(hold_ring_2=True) is FleetExit.OK
    assert release_env.merged() == ["beta", "alpha"]
    assert release_env.end()["gamma"] == "HELD" and f"gamma: guard-fleet land {TAG} --ring 2" in release_env.out()
    assert release_env.remote_branch("gamma") == ""                    # ring 2 was never published
    assert release_env.land(rings=(2,)) is FleetExit.OK                 # no env var needed without --rebuild
    assert release_env.merged() == ["beta", "alpha", "gamma"]
    assert len(release_env.confirm.reasons) == 2
    assert release_env.confirm.reasons[1] == f"land {TAG} ({release_env.t[:7]}): ring 2 gamma"


def _push_leftover(env, short):
    head = env.records(short, "merge")[-1].head
    _git(env.clones[short], "push", "-q", "origin", f"{head}:refs/heads/{BRANCH}")
    assert env.remote_branch(short) != ""


def test_rerun_reverifies_and_only_lists_cleanup_without_a_confirmation(release_env):
    assert release_env.release() is FleetExit.OK
    _push_leftover(release_env, "alpha")
    merges = len(release_env.merged())
    verified = len(release_env.records("alpha", "verify"))   # ring2_ready re-verifies ring 1 too
    assert release_env.release() is FleetExit.OK                        # a deferred cleanup is not "kept"
    assert len(release_env.confirm.reasons) == 1                        # nothing GATED: no second confirmation
    assert len(release_env.merged()) == merges
    assert release_env.remote_branch("alpha") != ""                     # R22.5: no deletion without a confirmation
    assert [r.detail["verdict"] for r in release_env.records("alpha", "verify")] == ["pass"] * (verified + 1)
    assert [r.detail["verdict"] for r in release_env.records("beta", "push-run")] == ["pass", "pass"]
    end = release_env.end()
    assert end["beta"] == end["gamma"] == "CURRENT"
    assert end["alpha"] == f"CURRENT (cleanup pending: {BRANCH} (remote))"
    assert f"alpha: guard-fleet cleanup {TAG} --remote\n" in release_env.out()


def test_rerun_cleanup_runs_after_this_runs_confirmation(release_env):
    assert release_env.release(hold_ring_2=True) is FleetExit.OK
    _push_leftover(release_env, "alpha")
    release_env.confirm = FakeConfirm(["cancelled", "approved"])
    assert release_env.land(rings=(2,)) is FleetExit.CANCELLED            # gamma re-gated, confirmation refused
    assert release_env.remote_branch("alpha") != ""                       # alpha re-verified, cleanup only listed
    assert release_env.land(rings=(2,)) is FleetExit.OK                   # approved: cleanup under that approval
    assert release_env.remote_branch("alpha") == ""
    assert release_env.end() == {"alpha": "CURRENT", "beta": "CURRENT", "gamma": "LANDED"}


def test_land_needs_the_env_var_only_with_rebuild(release_env):
    assert release_env.land(rebuild=("alpha",), lock_update=False) is FleetExit.USAGE
    assert f"Run: ALLOW_GUARD_LOCK_UPDATE=1 guard-fleet land {TAG} --rebuild alpha" in release_env.out()
    assert release_env.fake.argvs == []


def test_land_without_a_roll_lands_nothing_and_points_at_release(release_env):
    assert release_env.land() is FleetExit.BLOCKED
    assert release_env.confirm.reasons == [] and release_env.remote_side_effects() == []
    assert f"Run: ALLOW_GUARD_LOCK_UPDATE=1 guard-fleet release {TAG}" in release_env.out()


def _c1_only_leftover(env, short):
    """A release interrupted between C1 and C2: the consumer's hook refused the guard.lock commit once."""
    hook = env.clones[short] / ".git" / "hooks" / "pre-commit"
    hook.write_text('#!/bin/sh\nif git diff --cached --name-only | grep -qx guard.lock; then exit 1; fi\n')
    hook.chmod(0o755)
    assert env.release(only=(short,)) is FleetExit.BLOCKED
    assert env.end()[short] == "BLOCKED c2: c2: hook refused"
    hook.unlink()


def test_land_with_a_c1_only_leftover_blocks_before_any_write_and_points_at_release(release_env):
    _c1_only_leftover(release_env, "alpha")
    seen = len(release_env.calls)
    assert release_env.land(only=("alpha",)) is FleetExit.BLOCKED
    since = [a for a, _, _ in release_env.calls[seen:] if a[:1] == ("git",)]
    assert not [a for a in since if "commit" in a or "add" in a]            # nothing staged or committed
    assert release_env.end()["alpha"].startswith("BLOCKED c2: ")
    assert f"alpha: Run: ALLOW_GUARD_LOCK_UPDATE=1 guard-fleet release {TAG}\n" in release_env.out()
    assert f"alpha: guard-fleet land {TAG}" not in release_env.out()      # never a next command that loops


def test_land_with_a_c1_only_leftover_under_markers_has_no_ready_line(release_env):
    _c1_only_leftover(release_env, "alpha")
    release_env.deps.environ["CLAUDECODE"] = "1"
    assert release_env.land(only=("alpha",)) is FleetExit.BLOCKED
    out = release_env.out()
    land_out = out[out.rindex("CONSUMER  STATE"):]
    assert f"alpha: Run in your own terminal: guard-fleet release {TAG}" in land_out
    assert "ALLOW_GUARD_LOCK_UPDATE=1 guard-fleet" not in land_out and "Run: " not in land_out


def test_end_table_next_release_command_under_markers_has_no_ready_line(release_env):
    release_env.deps.environ["CLAUDECODE"] = "1"
    assert release_env.land() is FleetExit.BLOCKED
    out = release_env.out()
    assert f"alpha: Run in your own terminal: guard-fleet release {TAG}" in out
    assert "ALLOW_GUARD_LOCK_UPDATE=1 set by you" in out
    assert "ALLOW_GUARD_LOCK_UPDATE=1 guard-fleet" not in out and "Run: " not in out


def test_rebuild_outside_the_selected_ring_is_a_usage_error(release_env):
    with pytest.raises(UsageError, match="--rebuild alpha: it is in ring 1, not in --ring 2"):
        release_env.land(rings=(2,), rebuild=("alpha",), lock_update=True)
    assert release_env.calls == [] and release_env.fake.argvs == []    # before any lock, git or GitHub call


def test_land_regates_existing_worktrees_and_lands_them(release_env):
    release_env.confirm = FakeConfirm(["cancelled", "approved"])
    assert release_env.release() is FleetExit.CANCELLED                # rolled, never published
    assert release_env.land() is FleetExit.OK
    assert release_env.merged() == ["beta", "alpha", "gamma"]
    assert release_env.confirm.reasons[1].startswith(f"land {TAG}")
    assert len(release_env.records("alpha", "attempt-start")) == 2     # re-gated, not trusted from the release


def test_rebuild_rolls_afresh_and_is_flagged_in_the_approval(release_env):
    release_env.confirm = FakeConfirm(["cancelled", "approved"])
    assert release_env.release() is FleetExit.CANCELLED
    assert release_env.land(rebuild=("gamma",), lock_update=True) is FleetExit.OK
    assert release_env.merged() == ["beta", "alpha", "gamma"]
    c2 = [e for a, _, e in release_env.calls if a[:1] == ("git",) and "commit" in a and release_env.is_c2(a)]
    assert len(c2) == 4 and all("ALLOW_GUARD_LOCK_UPDATE" in e for e in c2)   # gamma's C2 ran again


# -- the env var reaches only C2 -------------------------------------------------------------------------------


def test_lock_update_reaches_only_c2_end_to_end(release_env):
    assert release_env.release(lock_update=True) is FleetExit.OK
    c2 = 0
    for argv, _, env in release_env.calls:
        assert ("ALLOW_GUARD_LOCK_UPDATE" in env) == (argv[:1] == ("git",) and "commit" in argv
                                                      and release_env.is_c2(argv))
        c2 += argv[:1] == ("git",) and "commit" in argv and release_env.is_c2(argv)
    assert c2 == 3


# -- the network lost during land (exit 4 or 6) ----------------------------------------------------------------


def _break_the_read_back_after_merge_of(monkeypatch, slug, exc):
    """The PR merges for real, then the local fetch of the default branch raises `exc`."""
    from guard_fleet import land as land_mod
    from guard_fleet.proc import Result
    orig, orig_fetch = gh_mod.Gh.pr_merge, land_mod.fetch_default
    broken = []

    def merge(self, s, number, head_sha):
        res = orig(self, s, number, head_sha)
        if s == slug:
            broken.append(s)
        return res

    def fetch(*a, **k):
        if broken:
            raise exc(Result(("git", "fetch"), 128, b"", b"fatal: read-back lost", False))
        return orig_fetch(*a, **k)
    monkeypatch.setattr(gh_mod.Gh, "pr_merge", merge)
    monkeypatch.setattr(land_mod, "fetch_default", fetch)
    return broken   # clear() it: the read-back works again


def _assert_failed_read_back(release_env):
    assert release_env.merged() == ["beta", "alpha"]
    end = release_env.end()
    assert end["beta"] == "LANDED"
    assert end["alpha"].startswith("FAILED merge: merge: PR #") and "but the read-back failed" in end["alpha"]
    assert "fatal: read-back lost" in end["alpha"]
    assert f"  alpha: {RESUME}" in release_env.out().rsplit("Next:", 1)[1]   # the one next command


def _lose_network_at_merge_of(monkeypatch, slug):
    orig = gh_mod.Gh.pr_merge

    def merge(self, s, number, head_sha):
        if s == slug:
            raise GhNetworkError(None, "network lost")
        return orig(self, s, number, head_sha)
    monkeypatch.setattr(gh_mod.Gh, "pr_merge", merge)


def test_network_lost_before_any_merge_is_cancelled_with_the_resume_command(release_env, monkeypatch):
    _lose_network_at_merge_of(monkeypatch, "owner/beta")
    assert release_env.release() is FleetExit.CANCELLED
    assert release_env.merged() == []
    assert f"Resume: {RESUME}" in release_env.deps.err.getvalue()


def test_network_lost_after_a_merge_is_failed_with_the_resume_command(release_env, monkeypatch):
    _lose_network_at_merge_of(monkeypatch, "owner/gamma")
    assert release_env.release() is FleetExit.FAILED
    assert release_env.merged() == ["beta", "alpha"]
    assert f"Resume: {RESUME}" in release_env.deps.err.getvalue()
    end = release_env.end()                                              # the end table is printed even so
    assert end["beta"] == end["alpha"] == "LANDED"
    assert end["gamma"] == "NOT RUN land: network lost: not merged"


def test_network_lost_in_the_read_back_after_a_merge_is_failed_exit_6(release_env, monkeypatch):
    from guard_fleet.git import GitNetworkError
    _break_the_read_back_after_merge_of(monkeypatch, "owner/alpha", GitNetworkError)
    assert release_env.release() is FleetExit.FAILED
    _assert_failed_read_back(release_env)


# -- a non-network git or gh error during land (exit 1 or 6, never a traceback) ---------------------------------


def test_a_git_lock_error_in_the_canary_cleanup_keeps_the_item_and_the_run_goes_on(release_env, monkeypatch):
    from guard_fleet import cleanup as cleanup_mod
    from guard_fleet.git import GitLockError
    from guard_fleet.proc import Result
    orig = cleanup_mod._default_head

    def head(ctx, consumer):
        if consumer.short == "beta":
            raise GitLockError(Result(("git", "fetch"), 128, b"", b"Unable to create 'x.lock': File exists.", False))
        return orig(ctx, consumer)
    monkeypatch.setattr(cleanup_mod, "_default_head", head)
    assert release_env.release() is FleetExit.BLOCKED                   # a kept cleanup item, not a traceback
    assert release_env.merged() == ["beta", "alpha", "gamma"]           # the canary's push-run gate ran, then the rest
    assert [r.detail["verdict"] for r in release_env.records("beta", "push-run")] == ["pass"]
    end = release_env.end()
    assert end["beta"].startswith("LANDED (cleanup kept: beta: kept: error: ") and "File exists" in end["beta"]
    assert end["alpha"] == end["gamma"] == "LANDED"


def _gh_error_at_merge_of(monkeypatch, slug):
    from guard_fleet.gh import GhError
    orig = gh_mod.Gh.pr_merge

    def merge(self, s, number, head_sha):
        if s == slug:
            raise GhError(403, "secondary rate limit")
        return orig(self, s, number, head_sha)
    monkeypatch.setattr(gh_mod.Gh, "pr_merge", merge)


def test_a_gh_error_after_verified_merges_prints_the_end_table_and_blocks(release_env, monkeypatch):
    _gh_error_at_merge_of(monkeypatch, "owner/gamma")
    assert release_env.release() is FleetExit.BLOCKED
    assert release_env.merged() == ["beta", "alpha"]
    err = release_env.deps.err.getvalue()
    assert "secondary rate limit" in err and f"Resume: {RESUME}" in err
    end = release_env.end()
    assert end["beta"] == end["alpha"] == "LANDED"
    assert end["gamma"].startswith("NOT RUN land: ") and "not merged" in end["gamma"]


def test_a_git_error_after_an_unverified_merge_is_failed(release_env, monkeypatch):
    from guard_fleet import land as land_mod
    from guard_fleet.git import GitError
    from guard_fleet.proc import Result
    orig = land_mod.Lander.verify

    def verify(self, consumer, rolled, merge_sha):
        if consumer.short == "alpha":
            raise GitError(Result(("git", "rev-parse"), 128, b"", b"fatal: odd", False))
        return orig(self, consumer, rolled, merge_sha)
    monkeypatch.setattr(land_mod.Lander, "verify", verify)
    assert release_env.release() is FleetExit.FAILED                    # merged, not verified: 6
    assert release_env.merged() == ["beta", "alpha"]
    assert f"Resume: {RESUME}" in release_env.deps.err.getvalue()
    end = release_env.end()
    assert end["beta"] == "LANDED" and end["alpha"].startswith("NOT RUN land: ") and "not verified" in end["alpha"]


def test_a_git_error_in_the_read_back_after_a_merge_is_failed_exit_6(release_env, monkeypatch):
    from guard_fleet.git import GitError
    _break_the_read_back_after_merge_of(monkeypatch, "owner/alpha", GitError)
    assert release_env.release() is FleetExit.FAILED
    _assert_failed_read_back(release_env)


def test_a_verified_resume_closes_the_read_back_failure_and_ring_2_goes_on(release_env, monkeypatch):
    from guard_fleet.git import GitNetworkError
    broken = _break_the_read_back_after_merge_of(monkeypatch, "owner/alpha", GitNetworkError)
    assert release_env.release() is FleetExit.FAILED
    assert release_env.merged() == ["beta", "alpha"]
    assert release_env.records("alpha", "merge")[-1].detail["readback"] is True
    broken.clear()                                                       # the blip is over
    assert release_env.release() is FleetExit.OK
    assert release_env.merged() == ["beta", "alpha", "gamma"]            # alpha is not merged twice; ring 2 landed
    assert release_env.end()["alpha"] == "CURRENT"
    assert release_env.records("alpha", "verify")[-1].detail["verdict"] == "pass"


def test_a_failed_canary_push_run_is_exit_6_and_nothing_else_merges(release_env):
    release_env.push_run_conclusion = "failure"
    assert release_env.release() is FleetExit.FAILED
    assert release_env.merged() == ["beta"]
    end = release_env.end()
    assert end["beta"].startswith("FAILED push-run: ") and end["alpha"].startswith("NOT RUN")


def test_no_helper_with_a_blocked_consumer_exits_1_before_any_push(tmp_path, fleet_home):
    env = ReleaseEnv(tmp_path, fleet_home, locks={"gamma": "not a lock\n"})
    env.confirm = FakeConfirm(["no_helper"])
    assert env.release() is FleetExit.BLOCKED                           # 1 outranks 5 (spec 6.12)
    assert env.remote_side_effects() == []
    gamma = env.end()["gamma"]
    assert gamma.startswith("BLOCKED plan: ") and gamma.endswith("guard.lock unparseable")


def test_plan_blocked_consumer_does_not_stop_the_others(tmp_path, fleet_home):
    env = ReleaseEnv(tmp_path, fleet_home, locks={"gamma": "not a lock\n"})
    assert env.release() is FleetExit.BLOCKED
    assert env.merged() == ["beta", "alpha"]
    assert env.confirm.reasons == [f"release {TAG} ({env.t[:7]}): ring 1 beta, alpha"]
    assert env.end()["gamma"] == "BLOCKED plan: plan: guard.lock unparseable"
