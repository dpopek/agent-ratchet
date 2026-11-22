"""Roll steps 1-5 against real fixture repositories (real git, routed uv and gh).

Task 14 extends this fixture: gate commands are routed by appending `Route`s to `env.routes`
(`ctx.deps.run.routes` is the same list), or `run_gates` is injected into `prepare`.
"""

import os
import subprocess

import pytest

from fakes import FakeGh, Route, make_deps
from guard_fleet.config import load_config
from guard_fleet.env import base_child_env
from guard_fleet.gh import Gh
from guard_fleet.git import Git, GitNetworkError
from guard_fleet.proc import Result
from guard_fleet.ledger import Ledger
from guard_fleet.lockfile import render_lock
from guard_fleet.names import branch_for, worktree_for
from guard_fleet.plan import PlanRow
from guard_fleet.roll import RollContext, hooks_line, prepare
from guard_fleet.target import Target
from repos import _env, _git, commit_files, make_bare, make_clone, make_upstream, push_all, redirect, sha_of

TAG = "v4.0.1"
GIT_AT = "git" + "@"  # kept apart so the hygiene scan does not read an origin URL as an e-mail address
OLD_SHIM = b"#!/bin/sh\necho old shim\n"
NEW_SHIM = b"#!/bin/sh\necho new shim\n"
PIN_URL = "git+https://github.com/dpopek/agent-ratchet@"
KINDS = {  # name -> (pin_kind, pin_file, extras)
    "alpha": ("req", "requirements-dev.txt", "php"),
    "beta": ("pyproject", "pyproject.toml", "none"),
    "gamma": ("none", None, "none"),
}
C1_MSG = "build(deps): pin agent-ratchet v4.0.1 in dev dependencies"


class RollEnv(tuple):
    """`(ctx, consumer, row)` for `prepare(*env)`, with the fixture's other handles as attributes."""

    def __new__(cls, ctx, consumer, row, **handles):
        obj = super().__new__(cls, (ctx, consumer, row))
        obj.__dict__.update(handles)
        return obj


def git_show(repo, spec) -> bytes:
    r = subprocess.run(("git", "show", spec), cwd=repo, env=_env(), capture_output=True, check=True,
                       stdin=subprocess.DEVNULL, timeout=60)
    return r.stdout


def commit_subjects(r) -> list[str]:
    out = _git(r.worktree, "log", "--reverse", "--format=%s", f"{r.base}..HEAD")
    return out.splitlines()


def pin_text(name, sha):
    if name == "alpha":
        return f"pytest==8\nagent-ratchet[php] @ {PIN_URL}{sha}\n"
    return f'[project]\nname = "demo"\ndependencies = [\n  "agent-ratchet @ {PIN_URL}{sha}",\n]\n'


def uv_lock_text(sha):
    return f'name = "agent-ratchet"\nsource = {{ git = "https://github.com/dpopek/agent-ratchet?rev={sha}#{sha}" }}\n'


def build_env(tmp_path, home, name, *, lock_update=False, default_branch="main", hook_needs=(),
              node_modules=False, extra_files=None):
    up = make_upstream(tmp_path / "up", {"v4.0.0": {"consumer/guard": OLD_SHIM}, TAG: {"consumer/guard": NEW_SHIM}})
    p, t = sha_of(up, "v4.0.0"), sha_of(up, TAG)
    kind, pin_file, extras = KINDS[name]
    gh_bare = make_bare(tmp_path / "gh", name)
    clone = make_clone(gh_bare, tmp_path / "repos" / name)
    files = {"README": "x\n", "guard.lock": render_lock(p, extras)}
    if pin_file:
        files[pin_file] = pin_text(name, p)
    if kind == "pyproject":
        files["uv.lock"] = uv_lock_text(p)
    for path, text in (extra_files or {}).items():
        files[path] = text.replace("@P@", p)
    commit_files(clone, "init", files)
    commit_files(clone, "shim", {"scripts/guard": OLD_SHIM}, mode="755")
    push_all(clone)
    url = f"https://github.com/owner/{name}"
    _git(clone, "remote", "set-url", "origin", url)
    redirect(home, url, gh_bare)
    if node_modules:
        (clone / "node_modules").mkdir()
    toml = [f'worktree_root = "{tmp_path}/wt"\n', "[[consumer]]", f'short = "{name}"', f'dir = "{clone}"',
            f'slug = "owner/{name}"', f'default_branch = "{default_branch}"', f'pin_kind = "{kind}"', "ring = 1",
            f"node_modules = {'true' if node_modules else 'false'}",
            "hook_needs = [" + ", ".join(f'"{h}"' for h in hook_needs) + "]"]
    if pin_file:
        toml.append(f'pin_file = "{pin_file}"')
    toml += ["[consumer.commit_env]", 'FLEET_COMMIT_NOTE = "kept"']
    cfg_path = home / ".config" / "guard-fleet" / "consumers.toml"
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    cfg_path.write_text("\n".join(toml) + "\n", encoding="utf-8")
    cfg = load_config(cfg_path, home=home)
    consumer = cfg.by_short(name)

    fakebin = tmp_path / "bin"
    fakebin.mkdir(exist_ok=True)
    for tool in ("uv", "uvx", "python3"):
        (fakebin / tool).write_text("#!/bin/sh\nexit 0\n")
        (fakebin / tool).chmod(0o755)
    environ = base_child_env(os.environ, tool_bin=tmp_path / "no-tool-bin")
    environ["HOME"] = str(home)
    environ["PATH"] = os.pathsep.join((str(fakebin), "/usr/bin", "/bin"))  # no real uv: a removed fake is missing

    def fake_uv_lock(argv, cwd, env):
        lock = cwd / "uv.lock"
        lock.write_text(lock.read_text().replace(p, t))

    fake_gh = FakeGh({f"owner/{name}": gh_bare})
    routes = [fake_gh.route(), Route(match=("uv", "lock"), effect=fake_uv_lock)]
    deps = make_deps(home, routes=routes, environ=environ)
    git = Git(deps.run, environ, deps.sleep)
    gh = Gh(deps.run, environ, deps.sleep, home)
    ledger = Ledger(deps.dirs.ledger(TAG), deps.clock)
    ctx = RollContext(deps, git, gh, up, cfg, Target(TAG, t, (4, 0, 1)), ledger, lock_update, environ)
    row = PlanRow(short=name, pin_tag="v4.0.0", p=p, extras=extras, t=t, d=sha_of(clone, "HEAD"), decision="BUMP",
                  reason="", evidence=(), exposure=None, provisional=False)
    return RollEnv(ctx, consumer, row, clone=clone, fake_gh=fake_gh, fakebin=fakebin, routes=routes, p=p, t=t,
                   branch=branch_for("4.0.1"), wt=worktree_for(cfg, consumer, "4.0.1"), home=home,
                   dirs=deps.dirs)


@pytest.fixture
def roll_env(tmp_path, fleet_home):
    def make(name, **kw):
        return build_env(tmp_path, fleet_home, name, **kw)
    return make


def refuse_lock_commits(env, path="guard.lock"):
    hook = env.clone / ".git" / "hooks" / "pre-commit"
    hook.write_text(f'#!/bin/sh\nif git diff --cached --name-only | grep -qx {path}; then\n'
                    '  echo "hook says no" >&2\n  exit 1\nfi\n')
    hook.chmod(0o755)
    return hook


def commit_calls(ctx):
    return [c for c in ctx.deps.run.calls if c[0][:1] == ("git",) and "commit" in c[0]]


# -- the happy path ----------------------------------------------------------


def test_roll_writes_two_commits_and_preserves_extras(roll_env):
    env = roll_env("alpha")
    r = prepare(*env)
    assert (r.state, r.step, r.reason) == ("GATED", "c2", "")
    assert r.gates == {} and r.manual_step is None
    assert r.worktree == env.wt and r.base == env[2].d and r.attempt == "alpha-1"
    assert git_show(r.worktree, "HEAD:guard.lock") == env.t.encode() + b"\nEXTRAS=php\n"
    assert commit_subjects(r) == [C1_MSG, f"chore(guard): bump agent-ratchet to v4.0.1 ({env.t})"]
    assert r.head == _git(r.worktree, "rev-parse", "HEAD")
    assert git_show(r.worktree, "HEAD:requirements-dev.txt") == pin_text("alpha", env.p).replace(
        env.p, env.t).encode()
    assert git_show(r.worktree, "HEAD:scripts/guard") == NEW_SHIM
    assert _git(r.worktree, "ls-files", "-s", "scripts/guard").startswith("100755 ")
    assert _git(r.worktree, "status", "--porcelain") == ""
    assert _git(r.worktree, "rev-parse", "--abbrev-ref", "HEAD") == env.branch
    assert r.hooks == "hooks: none"


def test_roll_ledger_has_one_record_per_step_in_one_attempt(roll_env):
    env = roll_env("alpha")
    r = prepare(*env)
    records, bad = env[0].ledger.records()
    assert bad == []
    assert [x.step for x in records] == ["attempt-start", "preflight", "base", "worktree", "c1", "c2"]
    assert {x.attempt for x in records} == {r.attempt}
    by_step = {x.step: x for x in records}
    assert by_step["base"].base == env[2].d
    assert by_step["c2"].head == r.head and by_step["c2"].rc == 0
    assert by_step["c2"].detail["hooks"] == "hooks: none"
    assert by_step["c2"].log == str(env.dirs.gate_log(TAG, "alpha", "c2"))


def test_pyproject_kind_regenerates_uv_lock_inside_c1(roll_env):
    env = roll_env("beta")
    r = prepare(*env)
    assert r.state == "GATED"
    assert git_show(r.worktree, "HEAD:guard.lock") == env.t.encode() + b"\n"  # extras none: no EXTRAS line
    assert git_show(r.worktree, "HEAD:uv.lock") == uv_lock_text(env.t).encode()
    assert _git(r.worktree, "show", "--name-only", "--format=", "HEAD~1").splitlines() == ["pyproject.toml",
                                                                                           "uv.lock"]
    uv = [c for c in env[0].deps.run.calls if c[0][:2] == ("uv", "lock")]
    assert [(argv, cwd) for argv, cwd, _ in uv] == [(("uv", "lock", "--quiet"), env.wt)]


def test_pin_kind_none_makes_one_commit(roll_env):
    env = roll_env("gamma")
    r = prepare(*env)
    assert r.state == "GATED"
    assert commit_subjects(r) == [f"chore(guard): bump agent-ratchet to v4.0.1 ({env.t})"]
    assert not any(c[0][:2] == ("uv", "lock") for c in env[0].deps.run.calls)
    assert [x.step for x in env[0].ledger.records()[0]] == ["attempt-start", "preflight", "base", "worktree", "c2"]


def test_lock_update_flag_reaches_only_c2(roll_env):
    env = roll_env("alpha", lock_update=True)
    prepare(*env)
    assert [("ALLOW_GUARD_LOCK_UPDATE" in e) for _, _, e in commit_calls(env[0])] == [False, True]


def test_commit_env_of_the_consumer_reaches_both_commits(roll_env):
    env = roll_env("alpha")
    prepare(*env)
    assert [e.get("FLEET_COMMIT_NOTE") for _, _, e in commit_calls(env[0])] == ["kept", "kept"]
    assert not any(k.startswith("ALLOW_") for _, _, e in commit_calls(env[0]) for k in e)


def test_roll_never_passes_no_verify(roll_env):
    env = roll_env("alpha")
    prepare(*env)
    assert not any("--no-verify" in argv or "-n" in argv for argv, _, _ in env[0].deps.run.calls)


def test_node_modules_is_symlinked_and_not_dirt(roll_env):
    env = roll_env("alpha", node_modules=True)
    r = prepare(*env)
    assert r.state == "GATED"
    link = r.worktree / "node_modules"
    assert link.is_symlink() and link.resolve() == (env.clone / "node_modules").resolve()


# -- preflight and base ------------------------------------------------------


def block_origin(env):
    _git(env.clone, "remote", "set-url", "origin", "https://github.com/owner/other")


def block_merge_commit(env):
    env.fake_gh.merge_commit_allowed["owner/alpha"] = False


def block_uv(env):
    (env.fakebin / "uv").unlink()


@pytest.mark.parametrize("tweak, word", [
    (block_origin, "origin"),
    (block_merge_commit, "merge commit"),
    (block_uv, "uv"),
])
def test_preflight_blocks_on_origin_mismatch_and_merge_commit_disallowed(roll_env, tweak, word):
    env = roll_env("alpha")
    tweak(env)
    r = prepare(*env)
    assert (r.state, r.step) == ("BLOCKED", "preflight")
    assert word in r.reason
    assert r.head is None and r.worktree is None
    assert not env.wt.exists()
    records, _ = env[0].ledger.records()
    assert [x.step for x in records] == ["attempt-start", "preflight", "attempt-end"]
    assert records[1].rc != 0 and records[-1].detail == {"ok": False}


@pytest.mark.parametrize("kw, word", [
    ({"default_branch": "develop"}, "default branch"),
    ({"hook_needs": ("no-such-tool",)}, "no-such-tool"),
    ({"hook_needs": ("{tmp}/missing/hook-tool",)}, "missing/hook-tool"),
    ({"node_modules": True}, "node_modules"),
])
def test_preflight_blocks_on_config_misses(roll_env, tmp_path, kw, word):
    kw = {k: (tuple(x.replace("{tmp}", str(tmp_path)) for x in v) if k == "hook_needs" else v)
          for k, v in kw.items()}
    env = roll_env("alpha", **kw)
    if kw.get("node_modules"):
        (env.clone / "node_modules").rmdir()
    r = prepare(*env)
    assert (r.state, r.step) == ("BLOCKED", "preflight")
    assert word in r.reason


def test_preflight_accepts_a_present_tool_and_a_scp_style_origin(roll_env):
    env = roll_env("alpha", hook_needs=("python3",))
    _git(env.clone, "config", f"url.file://{env.clone.parent.parent}/gh/alpha.git.insteadOf",
         GIT_AT + "github.com:owner/alpha.git")
    _git(env.clone, "remote", "set-url", "origin", GIT_AT + "github.com:owner/alpha.git")
    assert prepare(*env).state == "GATED"


@pytest.mark.parametrize("url", ["ssh://" + GIT_AT + "github.com/owner/alpha.git", "https://github.com/owner/alpha/"])
def test_preflight_normalises_origin_forms(roll_env, url):
    env = roll_env("alpha")
    gh_bare = env.clone.parent.parent / "gh" / "alpha.git"
    _git(env.clone, "config", f"url.file://{gh_bare}.insteadOf", url.rstrip("/"))
    _git(env.clone, "remote", "set-url", "origin", url)
    r = prepare(*env)
    assert r.state == "GATED"


def test_base_blocks_when_the_lock_differs_from_the_plan(roll_env):
    env = roll_env("alpha")
    ctx, consumer, row = env
    r = prepare(ctx, consumer, row.__class__(**{**row.__dict__, "extras": "none"}))
    assert (r.state, r.step) == ("BLOCKED", "base")
    assert "guard.lock" in r.reason
    assert not env.wt.exists()
    records, _ = ctx.ledger.records()
    assert [x.step for x in records] == ["attempt-start", "preflight", "base", "attempt-end"]


def test_base_blocks_when_d_is_not_in_the_clone(roll_env):
    env = roll_env("alpha")
    ctx, consumer, row = env
    r = prepare(ctx, consumer, row.__class__(**{**row.__dict__, "d": "f" * 40}))
    assert (r.state, r.step) == ("BLOCKED", "base")


# -- C1 and C2 ---------------------------------------------------------------


def test_pin_test_hardcoding_the_sha_blocks(roll_env):
    env = roll_env("alpha", extra_files={"tests/ci/test_guard_pin.py": 'PIN = "@P@"\n'})
    r = prepare(*env)
    assert (r.state, r.step) == ("BLOCKED", "c1")
    assert "pin test hard-codes the SHA; edit it by hand" in r.reason
    assert commit_calls(env[0]) == []
    assert env[0].ledger.records()[0][-1].detail == {"ok": False}


def test_hook_refusal_blocks_without_no_verify(roll_env):
    env = roll_env("alpha")
    refuse_lock_commits(env)
    r = prepare(*env)
    assert (r.state, r.step, r.reason) == ("BLOCKED", "c2", "c2: hook refused")
    assert r.worktree == env.wt and r.head is None
    assert "hook says no" in env.dirs.gate_log(TAG, "alpha", "c2").read_text()
    assert not any("--no-verify" in argv for argv, _, _ in env[0].deps.run.calls)
    assert r.hooks == "hooks: main checkout"
    records, _ = env[0].ledger.records()
    assert records[-1].step == "attempt-end" and records[-1].detail == {"ok": False}
    assert [x for x in records if x.step == "c2"][0].rc != 0


# -- resume ------------------------------------------------------------------


def test_resume_retries_interrupted_c2_with_fleet_dirt_only(roll_env):
    env = roll_env("alpha")
    hook = refuse_lock_commits(env)
    assert prepare(*env).state == "BLOCKED"
    hook.unlink()
    seen = len(env[0].deps.run.calls)
    r = prepare(*env)
    assert (r.state, r.attempt) == ("GATED", "alpha-2")
    assert commit_subjects(r) == [C1_MSG, f"chore(guard): bump agent-ratchet to v4.0.1 ({env.t})"]
    assert git_show(r.worktree, "HEAD:guard.lock") == env.t.encode() + b"\nEXTRAS=php\n"
    assert not any("worktree" in a and "add" in a for a, _, _ in env[0].deps.run.calls[seen:])
    assert r.base == env[2].d


def test_resume_of_a_finished_roll_goes_straight_to_the_gates(roll_env):
    env = roll_env("alpha")
    first = prepare(*env)
    seen = len(env[0].deps.run.calls)
    second = prepare(*env)
    assert (second.state, second.head, second.base) == ("GATED", first.head, first.base)
    assert len(commit_calls(env[0])) == 2  # the resume made no third commit
    assert not any("commit" in a for a, _, _ in env[0].deps.run.calls[seen:] if a[:1] == ("git",))


def test_resume_uses_the_merge_base_when_the_default_branch_moved(roll_env):
    env = roll_env("alpha")
    first = prepare(*env)
    commit_files(env.clone, "later", {"README": "y\n"})
    ctx, consumer, row = env
    second = prepare(ctx, consumer, row.__class__(**{**row.__dict__, "d": sha_of(env.clone, "HEAD")}))
    assert (second.state, second.base, second.head) == ("GATED", first.base, first.head)


@pytest.mark.parametrize("dirt", ["foreign file", "altered lock"])
def test_resume_blocks_on_dirt_that_is_not_the_fleets(roll_env, dirt):
    env = roll_env("alpha")
    hook = refuse_lock_commits(env)
    prepare(*env)
    hook.unlink()
    if dirt == "foreign file":
        (env.wt / "extra.txt").write_text("x\n")
    else:
        (env.wt / "guard.lock").write_text("not the fleet's bytes\n")
    r = prepare(*env)
    assert r.state == "BLOCKED"
    assert ("extra.txt" if dirt == "foreign file" else "guard.lock") in r.reason
    assert r.manual_step is None


def test_resume_blocks_on_a_foreign_commit(roll_env):
    env = roll_env("alpha")
    prepare(*env)
    commit_files(env.wt, "foreign", {"extra.txt": "x\n"})
    r = prepare(*env)
    assert r.state == "BLOCKED" and "commit" in r.reason


def test_resume_blocks_when_another_branch_sits_in_the_worktree(roll_env):
    env = roll_env("alpha")
    _git(env.clone, "worktree", "add", "-q", "-b", "other-topic", str(env.wt), env[2].d)
    r = prepare(*env)
    assert r.state == "BLOCKED" and "other-topic" in r.reason


def test_resume_blocks_when_the_branch_has_commits_but_no_worktree(roll_env):
    env = roll_env("alpha")
    prepare(*env)
    _git(env.clone, "worktree", "remove", str(env.wt))
    r = prepare(*env)
    assert r.state == "BLOCKED" and "worktree" in r.reason


def test_zero_commit_branch_and_initializing_lock_print_manual_step(roll_env):
    env = roll_env("alpha")
    _git(env.clone, "worktree", "add", "-q", "--no-track", "-b", env.branch, str(env.wt), env[2].d)
    r = prepare(*env)
    assert (r.state, r.manual_step) == ("BLOCKED", "guard-fleet cleanup")
    assert env.branch in r.reason or "0 commits" in r.reason
    _git(env.clone, "worktree", "lock", "--reason", "initializing", str(env.wt))
    r = prepare(*env)
    assert (r.state, r.manual_step) == ("BLOCKED", f"git worktree unlock {env.wt}, then guard-fleet cleanup")
    assert "initializing" in r.reason


def test_zero_commit_branch_without_worktree_prints_cleanup(roll_env):
    env = roll_env("alpha")
    _git(env.clone, "branch", env.branch, env[2].d)
    r = prepare(*env)
    assert (r.state, r.manual_step) == ("BLOCKED", "guard-fleet cleanup")


# -- hooks line --------------------------------------------------------------


def test_hooks_line_missing_hookspath_dir_is_none(roll_env):
    env = roll_env("alpha")
    _git(env.clone, "config", "core.hooksPath", ".husky/_")
    r = prepare(*env)
    assert r.state == "GATED" and r.hooks == "hooks: none"
    assert hooks_line(env[0].git, r.worktree) == "hooks: none"


def test_hooks_line_worktree_and_main_checkout(roll_env):
    env = roll_env("alpha")
    r = prepare(*env)
    git = env[0].git
    inside = r.worktree / ".hooks"
    inside.mkdir()
    (inside / "pre-commit").write_text("#!/bin/sh\nexit 0\n")
    (inside / "pre-commit").chmod(0o755)
    (inside / "not-a-hook").write_text("#!/bin/sh\n")
    (inside / "not-a-hook").chmod(0o755)
    _git(env.clone, "config", "core.hooksPath", ".hooks")
    assert hooks_line(git, r.worktree) == "hooks: worktree"
    (inside / "pre-commit").chmod(0o644)  # present but not executable
    assert hooks_line(git, r.worktree) == "hooks: none"
    _git(env.clone, "config", "--unset", "core.hooksPath")
    assert hooks_line(git, r.worktree) == "hooks: none"
    main_hook = env.clone / ".git" / "hooks" / "pre-commit"
    main_hook.write_text("#!/bin/sh\nexit 0\n")
    main_hook.chmod(0o755)
    assert hooks_line(git, r.worktree) == "hooks: main checkout"


# -- C1 resume (fix round 1) -----------------------------------------------


def start_worktree(env):
    _git(env.clone, "worktree", "add", "-q", "--no-track", "-b", env.branch, str(env.wt), env[2].d)


def test_resume_retries_interrupted_req_c1(roll_env):
    env = roll_env("alpha")
    hook = refuse_lock_commits(env, "requirements-dev.txt")
    first = prepare(*env)
    assert (first.state, first.step, first.reason) == ("BLOCKED", "c1", "c1: hook refused")
    hook.unlink()
    r = prepare(*env)
    assert (r.state, r.attempt) == ("GATED", "alpha-2")
    assert commit_subjects(r) == [C1_MSG, f"chore(guard): bump agent-ratchet to v4.0.1 ({env.t})"]


def test_resume_retries_pyproject_c1_when_uv_lock_is_untouched(roll_env):
    env = roll_env("beta")
    start_worktree(env)   # the interrupted C1 wrote the pin file and died before uv lock
    pin = env.wt / "pyproject.toml"
    pin.write_bytes(pin.read_bytes().replace(env.p.encode(), env.t.encode()))
    r = prepare(*env)
    assert r.state == "GATED"
    assert git_show(r.worktree, "HEAD:uv.lock") == uv_lock_text(env.t).encode()
    assert commit_subjects(r)[0] == C1_MSG


def test_resume_blocks_on_a_foreign_uv_lock(roll_env):
    env = roll_env("beta")
    start_worktree(env)
    (env.wt / "uv.lock").write_text(uv_lock_text(env.p) + "# foreign edit\n")
    r = prepare(*env)
    assert r.state == "BLOCKED" and "uv.lock" in r.reason
    assert commit_calls(env[0]) == []


def test_resume_blocks_when_a_refused_pyproject_c1_left_a_regenerated_uv_lock(roll_env):
    env = roll_env("beta")
    hook = refuse_lock_commits(env, "pyproject.toml")
    assert prepare(*env).reason == "c1: hook refused"
    hook.unlink()
    r = prepare(*env)
    assert r.state == "BLOCKED" and "uv.lock" in r.reason


# -- git network loss ----------------------------------------------------------


def test_git_network_loss_stops_the_run_instead_of_blocking(roll_env):
    env = roll_env("alpha")
    ctx = env[0]
    real = ctx.git.run

    def flaky(argv, **kw):
        if "fetch" in argv:
            return Result(tuple(argv), 128, b"", b"fatal: Could not resolve host: example.invalid", False)
        return real(argv, **kw)

    ctx.git.run = flaky
    with pytest.raises(GitNetworkError):
        prepare(*env)
    records, _ = ctx.ledger.records()
    assert records[-1].step == "attempt-end" and records[-1].detail == {"ok": False}
    assert not env.wt.exists()
