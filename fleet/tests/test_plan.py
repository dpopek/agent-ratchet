import dataclasses
import os
from pathlib import Path

import pytest

from fakes import FakeGh, Route, _http, make_deps, real_git
from guard_fleet.classify import Level
from guard_fleet.config import FleetConfig, load_config
from guard_fleet.env import base_child_env
from guard_fleet.exits import FleetExit, UsageError
from guard_fleet.locks import RunLock
from guard_fleet.mirror import UPSTREAM_URL
from guard_fleet.plan import Planner, run_plan
from guard_fleet.target import validate_target
from repos import _git, commit_files, make_bare, make_clone, make_upstream, push_all, redirect, sha_of, tag_annotated

REPO_ROOT = Path(__file__).resolve().parents[2]
CONFIG_PATH = "scripts/audit/audit_guard_config.json"
COMPARE = "src/agent_ratchet/php/compare.py"

# php.scan returns early unless the php profile is active, so php.compare is reachable only behind that gate.
GATED_SCAN = ("from agent_ratchet.php.scope import php_profile_active\n\n\n"
              "def php_scan(cfg):\n    if not php_profile_active(cfg):\n        return []\n"
              "    from agent_ratchet.php.compare import X\n    return [X]\n")
PYPROJECT = '[project]\nname = "demo"\nversion = "1.0.0"\n\n[project.scripts]\nagent-ratchet = "agent_ratchet.cli:main"\n'


def _release_files() -> dict[str, bytes | str]:
    """A release tree whose predicate and loader are byte-exact copies of this repository's, so every fingerprint
    is reviewed; the glue modules only wire the php surface behind the profile gate."""
    src = REPO_ROOT / "src/agent_ratchet"
    return {
        "pyproject.toml": PYPROJECT,
        "src/agent_ratchet/php/scope.py": (src / "php/scope.py").read_bytes(),
        "src/agent_ratchet/git_guard_io.py": (src / "git_guard_io.py").read_bytes(),
        "src/agent_ratchet/cli.py": "from agent_ratchet.transition_scan import run\n\n\ndef main():\n    return run()\n",
        "src/agent_ratchet/transition_scan.py": "from agent_ratchet.php.scan import php_scan\n\n\ndef run():\n    return php_scan({})\n",
        "src/agent_ratchet/php/scan.py": GATED_SCAN,
        COMPARE: "X = 1\n",
    }


class PlanEnv(tuple):
    """`(deps, cfg)` for `run_plan(*env, ...)`, with the fixture's other handles as attributes."""

    def __new__(cls, deps, cfg, **handles):
        obj = super().__new__(cls, (deps, cfg))
        obj.__dict__.update(handles)
        return obj


def build_env(tmp_path, home, *, locks=None, configs=None, hide=(), mode="ok"):
    """`locks` maps a short to a function of the upstream shas returning that consumer's guard.lock text (None: no
    file). Upstream tags v4.0.0 and v4.0.1 on main (v4.0.1 changes only php/compare.py) plus v4.0.8 on a side branch
    forked from v4.0.0; consumers alpha (core only) and beta (php profile), both pinned to v4.0.0."""
    bare = make_upstream(tmp_path / "up", {"v4.0.0": _release_files(), "v4.0.1": {COMPARE: "X = 2\n"}})
    side = make_clone(bare, tmp_path / "side-work")
    _git(side, "checkout", "-q", "-b", "side", "v4.0.0")
    commit_files(side, "side", {"s": "1"})
    tag_annotated(side, "v4.0.8")
    push_all(side)
    redirect(home, UPSTREAM_URL, bare)
    shas = {tag: sha_of(bare, tag) for tag in ("v4.0.0", "v4.0.1", "v4.0.8")}
    pinned = shas["v4.0.0"] + "\n"
    locks = {"alpha": pinned, "beta": pinned, **{k: v(shas) for k, v in (locks or {}).items()}}   # None = no file
    configs = {"alpha": None, "beta": b'{"languages": ["php"]}', **(configs or {})}
    bares, clones, toml = {}, {}, [f'worktree_root = "{tmp_path}/wt"\n']
    for short in ("alpha", "beta"):
        gh_bare = make_bare(tmp_path / "gh", short)
        clone = make_clone(gh_bare, tmp_path / "repos" / short)
        files: dict[str, bytes | str] = {"README": "x\n"}
        if locks[short] is not None:
            files["guard.lock"] = locks[short]
        if configs[short] is not None:
            files[CONFIG_PATH] = configs[short]
        commit_files(clone, "init", files)
        push_all(clone)
        redirect(home, f"https://github.com/owner/{short}", gh_bare)
        if short not in hide:
            bares[f"owner/{short}"] = gh_bare
        clones[short] = clone
        toml.append(f'[[consumer]]\nshort = "{short}"\ndir = "{clone}"\nslug = "owner/{short}"\n'
                    f'default_branch = "main"\npin_kind = "none"\nring = 1\n')
    cfg_path = home / ".config" / "guard-fleet" / "consumers.toml"
    cfg_path.parent.mkdir(parents=True)
    cfg_path.write_text("\n".join(toml), encoding="utf-8")
    gh = FakeGh(bares)
    if mode == "401":
        routes = [Route(match=lambda a: a[:1] == ("gh",), rc=4,
                        stderr=b"To get started with GitHub CLI, please run:  gh auth login")]
    elif mode == "429":
        routes = [Route(match=lambda a: a[:1] == ("gh",), effect=lambda a, c, e: _http(429, b"rate limited"))]
    else:
        routes = [gh.route()]
    environ = base_child_env(os.environ, tool_bin=Path("/nonexistent"))
    environ["HOME"] = str(home)
    deps = make_deps(home, routes=routes, environ=environ)
    return PlanEnv(deps, load_config(cfg_path, home=home), gh=gh, bare=bare, shas=shas, clones=clones, gh_bares=bares,
                   home=home)


@pytest.fixture
def plan_env(tmp_path, fleet_home):
    return build_env(tmp_path, fleet_home)


@pytest.fixture
def make_env(tmp_path, fleet_home):
    return lambda **kw: build_env(tmp_path, fleet_home, **kw)


@pytest.fixture
def plan_env_gh_401(make_env):
    return make_env(mode="401")


@pytest.fixture
def plan_env_gh_429(make_env):
    return make_env(mode="429")


@pytest.fixture
def plan_env_gh_404(make_env):
    return make_env(hide=("alpha",))


def rows(res):
    return {r.short: r for r in res.rows}


def test_fixture_release_is_a_clean_php_only_change(plan_env):
    # guards the fixture: if the copied sources stopped classifying cleanly, every SKIP below would be vacuous
    from guard_fleet.classify import classify_release
    from guard_fleet.mirror import refresh_mirror
    git = real_git()
    mirror = refresh_mirror(plan_env[0], git)
    rel = classify_release(git, mirror, plan_env.shas["v4.0.0"], plan_env.shas["v4.0.1"])
    assert rel.all_core_reason is None and rel.fingerprint_mismatch == () and rel.min_level is Level.PHP


def test_plan_skip_prints_evidence(plan_env):            # upstream v4.0.0 -> v4.0.1 changes only php/compare.py
    res = run_plan(*plan_env, "v4.0.1", only=(), include_unexposed=False)
    row = rows(res)["alpha"]
    assert row.decision == "SKIP" and "src/agent_ratchet/php/compare.py [php]" in row.evidence
    assert row.pin_tag == "v4.0.0" and row.p == plan_env.shas["v4.0.0"] and row.t == plan_env.shas["v4.0.1"]
    assert row.exposure.level is Level.CORE and not row.provisional
    assert res.target.tag == "v4.0.1" and res.mirror_note is None


def test_plan_bump_for_a_php_exposed_consumer(plan_env):
    res = run_plan(*plan_env, "v4.0.1", only=(), include_unexposed=False)
    beta = rows(res)["beta"]
    assert beta.decision == "BUMP" and beta.exposure.level is Level.PHP
    assert res.exit is FleetExit.OK and [r.short for r in res.rows] == ["alpha", "beta"]


def test_plan_include_unexposed_turns_skip_into_bump(plan_env):
    alpha = rows(run_plan(*plan_env, "v4.0.1", only=("alpha",), include_unexposed=True))["alpha"]
    assert alpha.decision == "BUMP" and alpha.reason == "--include-unexposed"


def test_plan_defaults_to_the_newest_tag_and_filters_with_only(plan_env):
    res = run_plan(*plan_env, None, only=("beta",), include_unexposed=False)
    assert res.target.tag == "v4.0.1" and [r.short for r in res.rows] == ["beta"]


def test_plan_unknown_only_is_a_usage_error_before_any_work(plan_env):
    with pytest.raises(UsageError):
        run_plan(*plan_env, "v4.0.1", only=("nope",), include_unexposed=False)
    assert not plan_env[0].dirs.state.exists()


def test_plan_current_pin(plan_env):
    res = run_plan(*plan_env, "v4.0.0", only=(), include_unexposed=False)
    assert {r.decision for r in res.rows} == {"CURRENT"} and res.exit is FleetExit.OK


@pytest.mark.parametrize("lock,reason", [
    (lambda shas: "d" * 40 + "\n", "untagged pin"),
    (lambda shas: shas["v4.0.8"] + "\n", "pin diverged from target"),
    (lambda shas: "not a lock\n", "guard.lock unparseable"),
    (lambda shas: None, "no guard.lock at ")])
def test_plan_untagged_diverged_unparseable_and_missing_locks_block(make_env, lock, reason):
    env = make_env(locks={"alpha": lock})
    res = run_plan(*env, "v4.0.1", only=(), include_unexposed=False)
    alpha, beta = res.rows
    assert alpha.decision == "BLOCKED" and alpha.exposure is None and alpha.d is not None
    assert alpha.reason == (reason + alpha.d if reason.endswith("at ") else reason)
    assert beta.decision == "BUMP"            # a blocked consumer does not stop the others
    assert res.exit is FleetExit.BLOCKED


def test_plan_missing_default_branch_blocks(plan_env):
    cfg = FleetConfig(plan_env[1].worktree_root,
                      (dataclasses.replace(plan_env[1].consumers[0], default_branch="trunk"),))
    row = run_plan(plan_env[0], cfg, "v4.0.1", only=(), include_unexposed=False).rows[0]
    assert row.decision == "BLOCKED" and row.reason == "default branch trunk not found" and row.d is None


def test_plan_missing_consumer_checkout_blocks(plan_env, tmp_path):
    cfg = FleetConfig(plan_env[1].worktree_root,
                      (dataclasses.replace(plan_env[1].consumers[0], dir=tmp_path / "absent"),))
    row = run_plan(plan_env[0], cfg, "v4.0.1", only=(), include_unexposed=False).rows[0]
    assert row.decision == "BLOCKED" and "missing" in row.reason


def test_plan_unfetchable_d_blocks(plan_env, tmp_path):
    other = make_clone(make_bare(tmp_path / "other", "alpha"), tmp_path / "other-work")
    commit_files(other, "unrelated", {"z": "1"})
    push_all(other)
    _push_new_head(plan_env, tmp_path, "alpha")      # D is now a commit the clone lacks ...
    _git(plan_env.clones["alpha"], "remote", "set-url", "origin", str(tmp_path / "other" / "alpha.git"))  # ... and cannot fetch
    row = run_plan(*plan_env, "v4.0.1", only=("alpha",), include_unexposed=False).rows[0]
    assert row.decision == "BLOCKED" and row.reason == "D not fetchable"


def _push_new_head(plan_env, tmp_path, short):
    work = make_clone(plan_env.gh_bares[f"owner/{short}"], tmp_path / f"adv-{short}")
    commit_files(work, "advance", {"extra.txt": "1\n"})
    push_all(work)


def test_plan_fetches_a_d_missing_from_the_clone(plan_env, tmp_path):
    _push_new_head(plan_env, tmp_path, "alpha")
    row = run_plan(*plan_env, "v4.0.1", only=("alpha",), include_unexposed=False).rows[0]
    assert row.decision == "SKIP" and not row.provisional and row.exposure.tree_scan.skipped is None
    assert row.d == sha_of(plan_env.gh_bares["owner/alpha"], "main")


def test_plan_lock_free_marks_skips_provisional(plan_env):
    run_plan(*plan_env, "v4.0.1", only=(), include_unexposed=False)      # seeds the mirror
    held = RunLock(plan_env[0].dirs.run_lock)
    assert held.acquire(exclusive=True)
    try:
        res = run_plan(*plan_env, "v4.0.1", only=(), include_unexposed=False)
    finally:
        held.release()
    assert res.mirror_note and res.mirror_note.startswith("mirror as of ")
    alpha, beta = res.rows
    assert (alpha.decision, alpha.provisional) == ("SKIP", True)
    assert (beta.decision, beta.provisional) == ("BUMP", False)


def test_plan_lock_free_without_a_mirror_is_a_usage_error(plan_env):
    held = RunLock(plan_env[0].dirs.run_lock)
    assert held.acquire(exclusive=True)
    try:
        with pytest.raises(UsageError):
            run_plan(*plan_env, "v4.0.1", only=(), include_unexposed=False)
    finally:
        held.release()


def test_plan_lock_free_skips_the_scan_when_d_is_not_in_the_clone(plan_env, tmp_path):
    run_plan(*plan_env, "v4.0.1", only=(), include_unexposed=False)
    _push_new_head(plan_env, tmp_path, "alpha")
    clone = plan_env.clones["alpha"]
    before = _git(clone, "for-each-ref")
    held = RunLock(plan_env[0].dirs.run_lock)
    assert held.acquire(exclusive=True)
    try:
        row = run_plan(*plan_env, "v4.0.1", only=("alpha",), include_unexposed=False).rows[0]
    finally:
        held.release()
    assert row.decision == "SKIP" and row.provisional
    assert row.exposure.tree_scan.skipped == "lock-free: D not in clone"
    assert _git(clone, "for-each-ref") == before


def test_plan_gh_auth_failure_blocks_each_consumer_with_message(plan_env_gh_401):
    res = run_plan(*plan_env_gh_401, "v4.0.1", only=(), include_unexposed=False)
    assert all(r.decision == "BLOCKED" and "gh auth" in r.reason for r in res.rows) and res.exit is FleetExit.CANCELLED
    assert len(res.rows) == 2


def test_plan_rate_limited_blocks_each_consumer(plan_env_gh_429):
    res = run_plan(*plan_env_gh_429, "v4.0.1", only=(), include_unexposed=False)
    assert all(r.decision == "BLOCKED" and "rate limited" in r.reason for r in res.rows)
    assert res.exit is FleetExit.CANCELLED


def test_plan_wrong_account_names_login(plan_env_gh_404):
    res = run_plan(*plan_env_gh_404, "v4.0.1", only=(), include_unexposed=False)
    assert res.rows[0].reason == "repo not visible to gh account operator" and res.exit is FleetExit.BLOCKED
    assert res.rows[1].decision == "BUMP"


def _snapshot(env):
    state = env.home / ".local" / "state" / "guard-fleet"
    files = {str(p.relative_to(state)): p.read_bytes() for p in sorted(state.rglob("*"))
             if p.is_file() and "agent-ratchet.git" not in p.relative_to(state).parts}
    mirror = _git(state / "agent-ratchet.git", "for-each-ref")
    clones = {short: (_git(c, "for-each-ref"), _git(c, "status", "--porcelain", "--ignored"),
                      _git(c, "worktree", "list")) for short, c in env.clones.items()}
    bares = {slug: _git(b, "for-each-ref") for slug, b in env.gh_bares.items()}
    listing = sorted(str(p.relative_to(env.home)) for p in (env.home / ".local").rglob("*")
                     if "agent-ratchet.git" not in p.parts)
    return files, mirror, clones, bares, listing


def test_plan_writes_nothing(plan_env):
    run_plan(*plan_env, "v4.0.1", only=(), include_unexposed=False)      # the first run creates the mirror
    before = _snapshot(plan_env)
    plan_env.gh.argvs.clear()
    run_plan(*plan_env, "v4.0.1", only=(), include_unexposed=True)
    assert _snapshot(plan_env) == before
    assert plan_env.gh.argvs, "the run made no gh call"
    for argv in plan_env.gh.argvs:
        assert argv[:3] == ("gh", "api", "-i") and "-X" not in argv, argv
        assert not {"create", "merge", "edit", "close"} & set(argv), argv


def test_planner_plans_one_consumer_for_reuse(plan_env):
    deps, cfg = plan_env
    git = real_git()
    from guard_fleet.mirror import refresh_mirror
    from guard_fleet.gh import Gh
    mirror = refresh_mirror(deps, git)
    planner = Planner(deps, git, Gh(deps.run, deps.environ, deps.sleep, deps.dirs.home), mirror, lock_free=False)
    target = validate_target(git, mirror, "v4.0.1")
    consumer = cfg.by_short("beta")
    assert planner.remote_url(consumer) == "https://github.com/owner/beta"
    row = planner.plan_consumer(consumer, target, include_unexposed=False)
    assert row.decision == "BUMP" and row.short == "beta" and planner.gh_stopped is False
