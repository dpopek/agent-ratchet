import dataclasses
import os
import stat
from pathlib import Path

import pytest

from fakes import Route, real_git
from guard_fleet import proc
from guard_fleet.config import FleetConfig
from guard_fleet.exits import UsageError
from guard_fleet.git import Git
from guard_fleet.locks import RunLock
from guard_fleet.status import StatusRow, collect_status, run_status
from guard_fleet.venvinfo import head_target, installed_commit
from repos import _git, commit_files, make_clone, push_all
from test_plan import build_env

CONFIG_PATH = "scripts/audit/audit_guard_config.json"


@pytest.fixture
def status_env(tmp_path, fleet_home):
    return build_env(tmp_path, fleet_home)


@pytest.fixture
def make_env(tmp_path, fleet_home):
    return lambda **kw: build_env(tmp_path, fleet_home, **kw)


def _route_venv_python(deps):
    """FakeRunner runs only git for real; let the fake venv interpreters (`python -I -c ...`) run too."""
    deps.run.routes.append(Route(match=lambda a: a[1:2] == ("-I",),
                                 effect=lambda a, cwd, env: proc.run(a, cwd=cwd, env=env, timeout=30)))


def by_short(report):
    return {r.short: r for r in report.rows}


def test_status_relations_and_zero_exit(status_env):
    deps, cfg = status_env
    report = collect_status(deps, cfg)
    rows = by_short(report)
    assert isinstance(rows["alpha"], StatusRow)
    assert rows["alpha"].relation == "BEHIND" and rows["alpha"].exposure_level == "core"
    assert (rows["alpha"].pin_tag, rows["alpha"].latest_tag, rows["alpha"].extras) == ("v4.0.0", "v4.0.1", "none")
    assert run_status(deps, cfg) == 0
    out = deps.out.getvalue()
    assert "alpha" in out and "BEHIND" in out and "v4.0.1" in out


def test_status_exposed_behind(status_env):      # beta has the php profile; v4.0.1 changes only php/compare.py
    rows = by_short(collect_status(*status_env))
    assert rows["beta"].relation == "EXPOSED-BEHIND" and rows["beta"].exposure_level == "php"
    assert rows["alpha"].relation == "BEHIND"
    run_status(*status_env)
    assert "EXPOSED-BEHIND" in status_env[0].out.getvalue()


def test_status_current_when_the_pin_is_the_latest_tag(make_env):
    env = make_env(locks={"alpha": lambda shas: shas["v4.0.1"] + "\n"})
    row = by_short(collect_status(*env))["alpha"]
    assert row.relation == "CURRENT" and row.pin_tag == "v4.0.1"


def test_status_gh_failure_reads_blocked_with_the_reason_and_still_exits_zero(make_env):
    env = make_env(mode="401")
    report = collect_status(*env)
    assert {r.relation for r in report.rows} == {"BLOCKED"}
    assert all("gh auth" in r.note for r in report.rows)
    assert run_status(*env) == 0
    out = env[0].out.getvalue()
    assert "BLOCKED" in out and "gh auth" in out and "CURRENT" not in out


def test_status_blocked_row_keeps_the_plan_reason(make_env):
    env = make_env(locks={"alpha": lambda shas: "d" * 40 + "\n"})
    row = by_short(collect_status(*env))["alpha"]
    assert row.relation == "BLOCKED" and row.note == "untagged pin"


def test_status_lists_open_fleet_prs_only(status_env):
    status_env.gh.prs["owner/alpha"] = [
        {"number": 7, "headRefName": "chore/agent-ratchet-4.4.1", "baseRefName": "main"},
        {"number": 8, "headRefName": "chore/agent-ratchet-migrate-imports", "baseRefName": "main"},
        {"number": 9, "headRefName": "feature/x", "baseRefName": "main"}]
    rows = by_short(collect_status(*status_env))
    assert rows["alpha"].open_fleet_prs == ("#7 chore/agent-ratchet-4.4.1",)
    assert rows["beta"].open_fleet_prs == ()


def _leftover_setup(env, tmp_path):
    clone = env.clones["alpha"]
    wt = tmp_path / "wt"
    wt.mkdir(exist_ok=True)
    _git(clone, "worktree", "add", "-q", "-b", "chore/agent-ratchet-4.3.3", str(wt / "alpha-wt-agent-ratchet-4.3.3"))
    _git(clone, "worktree", "add", "-q", "-b", "chore/agent-ratchet-4.3.4", str(wt / "alpha-wt-agent-ratchet-4.3.4"))
    _git(clone, "worktree", "lock", "--reason", "initializing", str(wt / "alpha-wt-agent-ratchet-4.3.4"))
    _git(clone, "worktree", "add", "-q", "-b", "foreign-topic", str(wt / "foreign"))      # not a fleet name
    _git(clone, "branch", "chore/agent-ratchet-4.3.2")
    _git(clone, "branch", "chore/agent-ratchet-migrate-imports")
    _git(clone, "push", "-q", "origin", "HEAD:refs/heads/chore/agent-ratchet-4.3.1")
    _git(clone, "push", "-q", "origin", "HEAD:refs/heads/chore/agent-ratchet-migrate-imports")
    return wt


def test_status_lists_leftovers_and_initializing_lock(status_env, tmp_path):
    wt = _leftover_setup(status_env, tmp_path)
    alpha = by_short(collect_status(*status_env))["alpha"]
    text = "\n".join(alpha.leftovers)
    assert f"worktree {wt / 'alpha-wt-agent-ratchet-4.3.3'} (chore/agent-ratchet-4.3.3)" in alpha.leftovers
    assert any("alpha-wt-agent-ratchet-4.3.4" in x and x.endswith("initializing") for x in alpha.leftovers)
    assert not any("initializing" in x for x in alpha.leftovers if "4.3.3" in x)
    assert "branch chore/agent-ratchet-4.3.2" in alpha.leftovers
    assert "remote chore/agent-ratchet-4.3.1" in alpha.leftovers
    assert "foreign" not in text and "migrate-imports" not in text
    assert by_short(collect_status(*status_env))["beta"].leftovers == ()
    run_status(*status_env)
    assert "initializing" in status_env[0].out.getvalue()


def test_status_reports_stale_index_lock_with_age(status_env):
    deps = status_env[0]
    gitdir = status_env.clones["alpha"] / ".git"
    old = deps.clock.wall() - 90 * 60
    wlock = gitdir / "worktrees" / "wt1" / "HEAD.lock"
    wlock.parent.mkdir(parents=True)
    ref_lock = gitdir / "refs" / "heads" / "main.lock"
    for path in (gitdir / "index.lock", wlock, ref_lock):
        path.write_text("")
        os.utime(path, (old, old))
    alpha = by_short(collect_status(*status_env))["alpha"]
    assert "index.lock (90 min)" in alpha.stale_locks
    assert "worktrees/wt1/HEAD.lock (90 min)" in alpha.stale_locks
    assert "refs/heads/main.lock (90 min)" in alpha.stale_locks
    assert by_short(collect_status(*status_env))["beta"].stale_locks == ()


def _fake_venv(root: Path, commit: str | None) -> Path:
    venv = root / "venv"
    (venv / "bin").mkdir(parents=True)
    py = venv / "bin" / "python"
    py.write_text("#!/bin/sh\n" + (f"echo {commit}\n" if commit else "exit 0\n"))
    py.chmod(py.stat().st_mode | stat.S_IXUSR)
    return venv


def _venv_env(env, tmp_path, installed):
    """alpha: pin file at HEAD names guard.lock's sha; a venv installed at `installed`; origin has one more commit."""
    clone = env.clones["alpha"]
    sha = env.shas["v4.0.0"]
    spec = f"agent-ratchet[php] @ git+https://github.com/dpopek/agent-ratchet@{sha}"
    commit_files(clone, "pin", {"requirements-dev.txt": f"pytest\n{spec}\n", "guard.lock": f"{sha}\nEXTRAS=php\n"})
    push_all(clone)
    work = make_clone(env.gh_bares["owner/alpha"], tmp_path / "adv")
    commit_files(work, "advance", {"later.txt": "1\n"})
    push_all(work)
    venv = _fake_venv(tmp_path / "alpha-venv", installed)
    alpha = dataclasses.replace(env[1].consumers[0], pin_kind="req", pin_file="requirements-dev.txt", venvs=(venv,))
    return FleetConfig(env[1].worktree_root, (alpha, env[1].consumers[1])), spec, sha


def test_status_venv_lines_installed_vs_head_lock_and_behind_origin(status_env, tmp_path):
    cfg, spec, sha = _venv_env(status_env, tmp_path, "e" * 40)
    _route_venv_python(status_env[0])
    alpha = by_short(collect_status(status_env[0], cfg))["alpha"]
    assert len(alpha.venv_lines) == 2
    assert alpha.venv_lines[0].endswith(f"installed {'e' * 8} vs HEAD lock {sha[:8]}")
    assert alpha.venv_lines[1].endswith("behind origin by 1")


def test_status_venv_in_step_with_head_and_origin_has_one_line(status_env, tmp_path):
    cfg, spec, sha = _venv_env(status_env, tmp_path, None)
    _route_venv_python(status_env[0])
    work = status_env.clones["alpha"]
    _git(work, "pull", "-q", "--ff-only")
    cfg2 = FleetConfig(cfg.worktree_root, (dataclasses.replace(cfg.consumers[0], venvs=(_fake_venv(tmp_path / "v2", sha),)),
                                            cfg.consumers[1]))
    alpha = by_short(collect_status(status_env[0], cfg2))["alpha"]
    assert len(alpha.venv_lines) == 1 and f"installed {sha[:8]} vs HEAD lock {sha[:8]}" in alpha.venv_lines[0]


def test_status_prints_the_fleets_own_pin_and_the_newest_tag_it_could_pin_to(status_env):
    deps = status_env[0]
    deps.dirs.self_lock.parent.mkdir(parents=True, exist_ok=True)
    deps.dirs.self_lock.write_text(status_env.shas["v4.0.0"] + "\n")
    report = collect_status(*status_env)
    assert report.self_pin == "v4.0.0" and report.latest.tag == "v4.0.1"
    run_status(*status_env)
    assert "self.lock pin: v4.0.0" in deps.out.getvalue() and "newest v4 tag: v4.0.1" in deps.out.getvalue()


def test_status_without_self_lock_says_so(status_env):
    assert collect_status(*status_env).self_pin is None
    run_status(*status_env)
    assert "self.lock pin: none" in status_env[0].out.getvalue()


def test_status_runs_lock_free_and_says_which_mirror(status_env):
    collect_status(*status_env)                        # seeds the mirror
    held = RunLock(status_env[0].dirs.run_lock)
    assert held.acquire(exclusive=True)
    try:
        assert run_status(*status_env) == 0
    finally:
        held.release()
    assert "mirror as of " in status_env[0].out.getvalue()


def test_status_marks_an_unscanned_behind_verdict_provisional(status_env, tmp_path):
    collect_status(*status_env)                        # seeds the mirror
    assert not by_short(collect_status(*status_env))["alpha"].provisional
    work = make_clone(status_env.gh_bares["owner/alpha"], tmp_path / "adv-alpha")
    commit_files(work, "advance", {"extra.txt": "1\n"})
    push_all(work)                                     # D is now absent from alpha's clone
    held = RunLock(status_env[0].dirs.run_lock)
    assert held.acquire(exclusive=True)
    try:
        rows = by_short(collect_status(*status_env))
        assert run_status(*status_env) == 0
    finally:
        held.release()
    assert rows["alpha"].relation == "BEHIND" and rows["alpha"].provisional
    assert not rows["beta"].provisional                # a BUMP verdict is never provisional
    out = status_env[0].out.getvalue()
    assert "BEHIND (provisional)" in out and "EXPOSED-BEHIND (provisional)" not in out


def test_status_unknown_mirror_in_lock_free_mode_is_a_usage_error(status_env):
    held = RunLock(status_env[0].dirs.run_lock)
    assert held.acquire(exclusive=True)
    try:
        with pytest.raises(UsageError):
            run_status(*status_env)
    finally:
        held.release()


def test_status_writes_no_ref_or_worktree_in_a_consumer(status_env):
    collect_status(*status_env)
    clone = status_env.clones["alpha"]
    before = (_git(clone, "for-each-ref"), _git(clone, "worktree", "list"), _git(clone, "status", "--porcelain"))
    status_env.gh.argvs.clear()
    collect_status(*status_env)
    assert (_git(clone, "for-each-ref"), _git(clone, "worktree", "list"), _git(clone, "status", "--porcelain")) == before
    assert not {"create", "merge", "edit", "close"} & {a for argv in status_env.gh.argvs for a in argv}


# -- venvinfo ---------------------------------------------------------------------------------------------------


def test_installed_commit_reads_direct_url(tmp_path):
    venv = _fake_venv(tmp_path, "f" * 40)
    env = {"PATH": os.environ.get("PATH", "")}
    assert installed_commit(proc.run, env, venv) == "f" * 40


def test_installed_commit_is_none_without_output_or_with_junk(tmp_path):
    env = {"PATH": os.environ.get("PATH", "")}
    assert installed_commit(proc.run, env, _fake_venv(tmp_path / "a", None)) is None
    assert installed_commit(proc.run, env, _fake_venv(tmp_path / "b", "not-a-sha")) is None
    assert installed_commit(proc.run, env, tmp_path / "missing") is None


def test_installed_commit_runs_isolated_and_reads_agent_ratchet_metadata(tmp_path):
    calls = []

    def run(argv, **kw):
        calls.append((tuple(argv), kw))
        return proc.Result(tuple(argv), 0, b"", b"", False)

    installed_commit(run, {}, tmp_path / "venv")
    argv = calls[0][0]
    assert argv[:3] == (str(tmp_path / "venv" / "bin" / "python"), "-I", "-c")
    assert "agent-ratchet" in argv[3] and "direct_url.json" in argv[3] and "commit_id" in argv[3]
    assert calls[0][1]["timeout"] > 0


def test_head_target_reads_pin_line_with_extras_and_lock(status_env, tmp_path):
    cfg, spec, sha = _venv_env(status_env, tmp_path, None)
    got = head_target(real_git(), status_env.clones["alpha"], cfg.consumers[0])
    assert got == (spec, sha, "")


def test_head_target_flags_a_pin_and_lock_that_disagree(status_env, tmp_path):
    cfg, spec, sha = _venv_env(status_env, tmp_path, None)
    commit_files(status_env.clones["alpha"], "lock moves", {"guard.lock": "9" * 40 + "\n"})
    got = head_target(real_git(), status_env.clones["alpha"], cfg.consumers[0])
    assert got == (spec, "9" * 40, "pin and lock disagree at HEAD")


def test_head_target_reads_a_pyproject_pin(status_env, tmp_path):
    sha = status_env.shas["v4.0.0"]
    spec = f"agent-ratchet @ git+https://github.com/dpopek/agent-ratchet@{sha}"
    clone = status_env.clones["alpha"]
    commit_files(clone, "pin", {"pyproject.toml": f'[dependency-groups]\ndev = [\n  "pytest",\n  "{spec}",\n]\n',
                                "guard.lock": sha + "\n"})
    consumer = dataclasses.replace(status_env[1].consumers[0], pin_kind="pyproject", pin_file="pyproject.toml")
    assert head_target(real_git(), clone, consumer) == (spec, sha, "")


def test_head_target_without_a_pin_kind_has_no_spec(status_env):
    got = head_target(real_git(), status_env.clones["alpha"], status_env[1].consumers[0])
    assert got[0] is None and got[1] == status_env.shas["v4.0.0"] and got[2] == ""
