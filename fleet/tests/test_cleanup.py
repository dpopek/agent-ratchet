"""Cleanup of fleet leftovers against real fixture repositories (real git, FakeGh for pull requests).

Every consumer is a clone of a local bare repository; the upstream mirror is a local bare repository too.
`git_calls()` lists the git argv (without the safety flags) the code under test ran since the last `item(...)`.
"""

import os
from pathlib import Path

import pytest

from fakes import FakeConfirm, FakeGh, make_deps
from guard_fleet import cleanup
from guard_fleet.cleanup import (IGNORED_ALLOWLIST, CleanupContext, Item, cleanup_landed, collect, execute,
                                 run_cleanup, safety)
from guard_fleet.config import load_config
from guard_fleet.confirm import AGENT_SUFFIX
from guard_fleet.env import base_child_env
from guard_fleet.exits import FleetExit, UsageError
from guard_fleet.gh import Gh
from guard_fleet.git import GIT_SAFE, Git, GitError, rev_parse
from guard_fleet.locks import RunLock
from guard_fleet.proc import Result
from guard_fleet.lockfile import render_lock
from guard_fleet.mirror import UPSTREAM_URL, refresh_mirror
from guard_fleet.names import branch_for, worktree_for
from repos import _git, commit_files, make_bare, make_clone, make_upstream, push_all, redirect, sha_of

OLD_SHIM = b"#!/bin/sh\necho old shim\n"
NEW_SHIM = b"#!/bin/sh\necho new shim\n"
SHORTS = ("alpha", "beta")
VERSION = "4.0.1"


def index_of(calls, *prefix):
    """Index of the first call whose leading arguments start with the given strings (prefix match per argument)."""
    for i, call in enumerate(calls):
        if len(call) >= len(prefix) and all(arg.startswith(want) for arg, want in zip(call, prefix)):
            return i
    raise AssertionError(f"no git call starting with {prefix!r} in {calls!r}")


def subargs(calls):
    return list(calls)


class CleanupEnv:
    def __init__(self, tmp_path: Path, home: Path, *, environ_extra=None, confirms=8):
        self.tmp = tmp_path
        self.home = home
        self.up = make_upstream(tmp_path / "up", {"v4.0.0": {"consumer/guard": OLD_SHIM},
                                                  "v4.0.1": {"consumer/guard": NEW_SHIM}})
        redirect(home, UPSTREAM_URL, self.up)
        self.p, self.t = sha_of(self.up, "v4.0.0"), sha_of(self.up, "v4.0.1")
        self.bares: dict[str, Path] = {}
        self.clones: dict[str, Path] = {}
        toml = [f'worktree_root = "{tmp_path}/wt"\n']
        for name in SHORTS:
            bare = make_bare(tmp_path / "gh", name)
            clone = make_clone(bare, tmp_path / "repos" / name)
            commit_files(clone, "init", {"README": "x\n", "guard.lock": render_lock(self.p, "none")})
            commit_files(clone, "shim", {"scripts/guard": OLD_SHIM}, mode="755")
            push_all(clone)
            url = f"https://github.com/owner/{name}"
            _git(clone, "remote", "set-url", "origin", url)
            redirect(home, url, bare)
            (clone / "node_modules").mkdir()
            self.bares[name], self.clones[name] = bare, clone
            toml += ["[[consumer]]", f'short = "{name}"', f'dir = "{clone}"', f'slug = "owner/{name}"',
                     'default_branch = "main"', 'pin_kind = "none"', "ring = 1", "node_modules = true",
                     "hook_needs = []\n"]
        cfg_path = home / ".config" / "guard-fleet" / "consumers.toml"
        cfg_path.parent.mkdir(parents=True, exist_ok=True)
        cfg_path.write_text("\n".join(toml) + "\n", encoding="utf-8")
        self.cfg = load_config(cfg_path, home=home)

        environ = base_child_env(os.environ, tool_bin=tmp_path / "no-tool-bin")
        environ["HOME"] = str(home)
        environ.update(environ_extra or {})
        self.fake_gh = FakeGh({f"owner/{n}": b for n, b in self.bares.items()})
        self.confirm = FakeConfirm(["approved"] * confirms)
        self.deps = make_deps(home, routes=[self.fake_gh.route()], confirm=self.confirm, environ=environ)
        self.git = Git(self.deps.run, environ, self.deps.sleep)
        self.gh = Gh(self.deps.run, environ, self.deps.sleep, home)
        self.mirror = refresh_mirror(self.deps, self.git)
        self.ctx = CleanupContext(self.deps, self.git, self.gh, self.mirror, self.cfg)
        self._mark = len(self.deps.run.calls)

    # -- queries -------------------------------------------------------------

    def consumer(self, name):
        return self.cfg.by_short(name)

    def wt(self, name, version=VERSION) -> Path:
        return worktree_for(self.cfg, self.consumer(name), version)

    def git_calls(self):
        calls = self.deps.run.calls[self._mark:]
        return [args[1 + len(GIT_SAFE):] for args, _cwd, _env in calls if args[:1] == ("git",)]

    def git_cwds(self, *prefix):
        calls = self.deps.run.calls[self._mark:]
        return [cwd for args, cwd, _env in calls
                if args[:1] == ("git",) and args[1 + len(GIT_SAFE):][: len(prefix)] == prefix]

    def remote_branches(self, name) -> list[str]:
        out = _git(self.bares[name], "for-each-ref", "--format=%(refname:short)", "refs/heads/chore/")
        return out.split()

    def local_ref(self, name, ref):
        return _git(self.clones[name], "rev-parse", "--verify", "--quiet", ref) if self._has_ref(name, ref) else None

    def _has_ref(self, name, ref) -> bool:
        return bool(_git(self.clones[name], "for-each-ref", ref))

    # -- builders ------------------------------------------------------------

    def _bump_commit(self, wt: Path, version: str, *, foreign: bool) -> str:
        sha = commit_files(wt, f"chore(guard): bump agent-ratchet to v{version} ({self.t})",
                           {"guard.lock": render_lock(self.t, "none"), "scripts/guard": NEW_SHIM})
        if foreign:
            sha = commit_files(wt, "unrelated work", {"README": "changed\n"})
        return sha

    def item(self, name, version=VERSION, *, remote=False) -> Item:
        self._mark = len(self.deps.run.calls)
        found = [i for i in collect(self.ctx, self.consumer(name), version=version, remote=remote)
                 if i.version == version]
        assert len(found) == 1, found
        return found[0]

    def leftover(self, name, version=VERSION, *, node_modules=False, merged=False, remote=False,
                 foreign=False, collect_remote=None) -> Item:
        clone, b, wt = self.clones[name], branch_for(version), self.wt(name, version)
        _git(clone, "worktree", "add", "-q", "-b", b, str(wt), "origin/main")
        sha = self._bump_commit(wt, version, foreign=foreign)
        if node_modules:
            os.symlink(clone / "node_modules", wt / "node_modules")
        if merged:
            _git(clone, "push", "-q", "origin", f"{sha}:refs/heads/main")
        if remote:
            _git(clone, "push", "-q", "origin", f"{b}:refs/heads/{b}")
        return self.item(name, version, remote=remote if collect_remote is None else collect_remote)

    def merged_leftover(self, name, version=VERSION, **kw) -> Item:
        return self.leftover(name, version, merged=True, **kw)

    def remote_only(self, name, version=VERSION, *, merged=False, foreign=False) -> Item:
        work = make_clone(self.bares[name], self.tmp / "pusher" / f"{name}-{version}")
        _git(work, "checkout", "-q", "-b", branch_for(version))
        sha = self._bump_commit(work, version, foreign=foreign)
        _git(work, "push", "-q", "origin", f"HEAD:refs/heads/{branch_for(version)}")
        if merged:
            _git(work, "push", "-q", "origin", f"{sha}:refs/heads/main")
        return self.item(name, version, remote=True)

    def make_branch(self, name, branch):
        _git(self.clones[name], "branch", branch, "main")

    def make_worktree(self, name, dirname, branch) -> Path:
        path = self.cfg.worktree_root / dirname
        _git(self.clones[name], "worktree", "add", "-q", "-b", branch, str(path), "main")
        return path

    def hook(self, name, body):
        hook = self.clones[name] / ".git" / "hooks" / "pre-push"
        hook.write_text("#!/bin/sh\n" + body + "\n")
        hook.chmod(0o755)

    def ignore(self, name, *patterns):
        exclude = self.clones[name] / ".git" / "info" / "exclude"
        exclude.parent.mkdir(exist_ok=True)
        exclude.write_text("\n".join(patterns) + "\n")


@pytest.fixture
def cleanup_env(tmp_path, fleet_home):
    return CleanupEnv(tmp_path, fleet_home)


def branch_exists(env, name, version=VERSION) -> bool:
    return bool(_git(env.clones[name], "for-each-ref", f"refs/heads/{branch_for(version)}"))


# -- execute: ordering and exact commands ---------------------------------------------------------------


def test_symlink_unlinked_before_remove_and_compare_and_delete(cleanup_env):
    item = cleanup_env.merged_leftover("alpha", "4.0.1", node_modules=True)
    wt = cleanup_env.wt("alpha")
    assert (wt / "node_modules").is_symlink()
    ok, _ = execute(cleanup_env.ctx, item)
    calls = cleanup_env.git_calls()
    assert ok and index_of(calls, "worktree", "remove") < index_of(calls, "update-ref", "-d")
    assert ("update-ref", "-d", "refs/heads/chore/agent-ratchet-4.0.1", item.local_head) in subargs(calls)
    assert not wt.exists() and not branch_exists(cleanup_env, "alpha")
    assert (cleanup_env.clones["alpha"] / "node_modules").is_dir()   # the symlink target is untouched


def test_foreign_node_modules_is_left_alone_and_keeps_worktree(cleanup_env):
    item = cleanup_env.merged_leftover("alpha")
    wt = cleanup_env.wt("alpha")
    elsewhere = cleanup_env.tmp / "elsewhere"
    elsewhere.mkdir()
    os.symlink(elsewhere, wt / "node_modules")
    ok, line = execute(cleanup_env.ctx, item)
    assert not ok and (wt / "node_modules").is_symlink() and os.readlink(wt / "node_modules") == str(elsewhere)
    assert wt.is_dir() and branch_exists(cleanup_env, "alpha") and "kept" in line


@pytest.mark.parametrize("dirty", ["untracked", "ignored-unlisted"])
def test_untracked_or_unlisted_ignored_file_keeps_worktree(cleanup_env, dirty):
    item = cleanup_env.merged_leftover("alpha")
    wt = cleanup_env.wt("alpha")
    if dirty == "untracked":
        (wt / "x.txt").write_text("x\n")
    else:
        cleanup_env.ignore("alpha", "build/")
        (wt / "build").mkdir()
        (wt / "build" / "out.o").write_text("o\n")
    ok, line = execute(cleanup_env.ctx, item)
    calls = cleanup_env.git_calls()
    assert not ok and "kept" in line
    assert wt.is_dir() and branch_exists(cleanup_env, "alpha")
    assert not any(c[:2] == ("worktree", "remove") or c[:2] == ("update-ref", "-d") for c in calls)


def test_allowlisted_ignored_entries_do_not_keep_worktree(cleanup_env):
    assert set(IGNORED_ALLOWLIST) == {".pytest_cache", "__pycache__", ".mypy_cache", ".ruff_cache"}
    item = cleanup_env.merged_leftover("alpha")
    wt = cleanup_env.wt("alpha")
    cleanup_env.ignore("alpha", ".pytest_cache/", "__pycache__/", ".mypy_cache/", ".ruff_cache/")
    for rel in (".pytest_cache", "pkg/__pycache__", ".mypy_cache", ".ruff_cache"):
        (wt / rel).mkdir(parents=True)
        (wt / rel / "f").write_text("f\n")
    ok, _ = execute(cleanup_env.ctx, item)
    assert ok and not wt.exists() and not branch_exists(cleanup_env, "alpha")


def test_never_force_and_never_fetch_prune(cleanup_env):
    item = cleanup_env.merged_leftover("alpha", node_modules=True, remote=True)
    cleanup_env.git(cleanup_env.clones["alpha"], "fetch", "-q", "origin")   # makes a tracking ref exist
    ok, _ = execute(cleanup_env.ctx, item)
    calls = cleanup_env.git_calls()
    assert ok
    flat = [arg for call in calls for arg in call]
    for banned in ("--force", "-f", "--prune", "-p", "-D", "--no-verify", "--delete"):
        assert banned not in flat, banned
    assert all(a.startswith("--force-with-lease=refs/heads/chore/agent-ratchet-4.0.1:")
               for a in flat if a.startswith("--force"))
    assert not [c for c in calls if c[:1] == ("fetch",) and "--prune" in c]
    removes = [c for c in calls if c[:2] == ("worktree", "remove")]
    assert removes == [("worktree", "remove", str(cleanup_env.wt("alpha")))]


# -- safety ----------------------------------------------------------------------------------------------


def test_merged_branch_is_safe_with_evidence(cleanup_env):
    item = cleanup_env.merged_leftover("alpha")
    assert item.safe and item.reason.startswith("merged into ")
    assert any("merged into" in line for line in item.evidence)


def test_unmerged_fleet_only_branch_is_safe(cleanup_env):
    item = cleanup_env.leftover("alpha")
    assert item.safe and item.reason == "fleet content only"
    ok, _ = execute(cleanup_env.ctx, item)
    assert ok and not cleanup_env.wt("alpha").exists()


def test_unmerged_branch_with_foreign_commit_is_kept(cleanup_env):
    item = cleanup_env.leftover("alpha", foreign=True)
    assert not item.safe and "README" in item.reason
    ok, line = execute(cleanup_env.ctx, item)
    assert not ok and "kept" in line
    assert cleanup_env.wt("alpha").is_dir() and branch_exists(cleanup_env, "alpha")
    assert not [c for c in cleanup_env.git_calls() if c[:2] in (("worktree", "remove"), ("update-ref", "-d"))]


def test_unmerged_fleet_only_branch_with_open_pr_is_kept(cleanup_env):
    cleanup_env.fake_gh.prs["owner/alpha"] = [{"number": 7, "state": "OPEN", "baseRefName": "main",
                                               "headRefName": branch_for(VERSION)}]
    item = cleanup_env.leftover("alpha")
    assert not item.safe and "open PR" in item.reason
    ok, _ = execute(cleanup_env.ctx, item)
    assert not ok and cleanup_env.wt("alpha").is_dir() and branch_exists(cleanup_env, "alpha")


def test_open_pr_does_not_block_a_merged_branch(cleanup_env):
    cleanup_env.fake_gh.prs["owner/alpha"] = [{"number": 7, "state": "OPEN", "baseRefName": "main",
                                               "headRefName": branch_for(VERSION)}]
    item = cleanup_env.merged_leftover("alpha")
    assert item.safe and execute(cleanup_env.ctx, item)[0]


def test_safety_unparseable_lock_is_unsafe(cleanup_env):
    clone = cleanup_env.clones["alpha"]
    bad = commit_files(clone, "bad lock", {"guard.lock": "garbage\n"})
    d = sha_of(cleanup_env.bares["alpha"], "main")
    ok, reason = safety(cleanup_env.git, clone, cleanup_env.mirror, cleanup_env.consumer("alpha"), bad, d, False)
    assert not ok and "guard.lock" in reason


def test_safety_ancestry_error_propagates(cleanup_env):
    clone = cleanup_env.clones["alpha"]
    d = sha_of(cleanup_env.bares["alpha"], "main")
    with pytest.raises(GitError):
        safety(cleanup_env.git, clone, cleanup_env.mirror, cleanup_env.consumer("alpha"), "0" * 40, d, False)


def test_item_with_an_ancestry_error_is_kept_and_reported(cleanup_env, monkeypatch):
    item = cleanup_env.leftover("alpha")

    def broken(*_a, **_k):
        raise GitError(Result(("git", "merge-base"), 128, b"", b"fatal: bad object", False))

    monkeypatch.setattr(cleanup, "safety", broken)
    ok, line = execute(cleanup_env.ctx, item)
    assert not ok and "kept" in line and "error" in line and "bad object" in line
    assert cleanup_env.wt("alpha").is_dir() and branch_exists(cleanup_env, "alpha")


# -- remote steps ----------------------------------------------------------------------------------------


def test_remote_delete_uses_lease_from_w_before_worktree_remove(cleanup_env):
    item = cleanup_env.merged_leftover("alpha", remote=True)
    b = branch_for(VERSION)
    assert item.remote_head == item.local_head
    assert cleanup_env.remote_branches("alpha") == [b]
    ok, _ = execute(cleanup_env.ctx, item)
    calls = cleanup_env.git_calls()
    push = (("push", f"--force-with-lease=refs/heads/{b}:{item.remote_head}", "origin", f":refs/heads/{b}"))
    assert ok and push in subargs(calls)
    assert index_of(calls, "push", f"--force-with-lease=refs/heads/{b}") < index_of(calls, "worktree", "remove")
    assert cleanup_env.git_cwds("push") == [cleanup_env.wt("alpha")]
    assert cleanup_env.remote_branches("alpha") == []


def test_remote_already_gone_is_fine(cleanup_env):
    item = cleanup_env.merged_leftover("alpha", remote=True)
    _git(cleanup_env.bares["alpha"], "update-ref", "-d", f"refs/heads/{branch_for(VERSION)}")   # delete-on-merge
    ok, _ = execute(cleanup_env.ctx, item)
    assert ok and not cleanup_env.wt("alpha").exists() and not branch_exists(cleanup_env, "alpha")
    assert not [c for c in cleanup_env.git_calls() if c[:1] == ("push",)]


def test_failed_push_with_branch_gone_afterwards_is_fine(cleanup_env):
    item = cleanup_env.merged_leftover("alpha", remote=True)
    b = branch_for(VERSION)
    cleanup_env.hook("alpha", f'git --git-dir="{cleanup_env.bares["alpha"]}" update-ref -d refs/heads/{b}\nexit 1')
    ok, _ = execute(cleanup_env.ctx, item)
    assert ok and not cleanup_env.wt("alpha").exists() and not branch_exists(cleanup_env, "alpha")
    assert cleanup_env.remote_branches("alpha") == []


def test_pre_push_refusal_keeps_everything(cleanup_env):
    item = cleanup_env.merged_leftover("alpha", remote=True, node_modules=True)
    b = branch_for(VERSION)
    cleanup_env.hook("alpha", 'echo "hook says no" >&2\nexit 1')
    ok, line = execute(cleanup_env.ctx, item)
    assert not ok and "hook says no" in line and "kept" in line
    assert cleanup_env.remote_branches("alpha") == [b]
    assert cleanup_env.wt("alpha").is_dir() and branch_exists(cleanup_env, "alpha")
    assert not [c for c in cleanup_env.git_calls() if c[:2] in (("worktree", "remove"), ("update-ref", "-d"))]


def test_lease_mismatch_keeps_everything(cleanup_env):
    item = cleanup_env.merged_leftover("alpha", remote=True)
    b = branch_for(VERSION)
    racer = make_clone(cleanup_env.bares["alpha"], cleanup_env.tmp / "racer")
    _git(racer, "checkout", "-q", b)
    moved = commit_files(racer, "late push", {"late": "1"})
    _git(racer, "push", "-q", "origin", f"{moved}:refs/heads/racer-tmp")
    # between the safety check and the push the remote branch moves: the lease must fail
    cleanup_env.hook("alpha", f'git --git-dir="{cleanup_env.bares["alpha"]}" update-ref refs/heads/{b} {moved}')
    ok, line = execute(cleanup_env.ctx, item)
    assert not ok and "kept" in line
    assert _git(cleanup_env.bares["alpha"], "rev-parse", f"refs/heads/{b}") == moved
    assert cleanup_env.wt("alpha").is_dir() and branch_exists(cleanup_env, "alpha")


def test_remote_only_leftover_is_deleted_from_the_main_clone(cleanup_env):
    assert collect(cleanup_env.ctx, cleanup_env.consumer("alpha"), version=None, remote=False) == []
    item = cleanup_env.remote_only("alpha")
    assert item.worktree is None and item.local_head is None and item.remote_head and item.safe
    ok, _ = execute(cleanup_env.ctx, item)
    assert ok and cleanup_env.remote_branches("alpha") == []
    assert cleanup_env.git_cwds("push") == [cleanup_env.clones["alpha"]]


def test_remote_only_branch_with_foreign_commit_is_kept(cleanup_env):
    item = cleanup_env.remote_only("alpha", foreign=True)
    assert not item.safe
    ok, _ = execute(cleanup_env.ctx, item)
    assert not ok and cleanup_env.remote_branches("alpha") == [branch_for(VERSION)]


def test_local_safe_but_remote_unsafe_keeps_everything(cleanup_env):
    item = cleanup_env.leftover("alpha", remote=True)
    b = branch_for(VERSION)
    work = make_clone(cleanup_env.bares["alpha"], cleanup_env.tmp / "pusher2")
    _git(work, "checkout", "-q", b)
    commit_files(work, "foreign", {"README": "changed\n"})
    _git(work, "push", "-q", "origin", f"HEAD:refs/heads/{b}")
    ok, _ = execute(cleanup_env.ctx, item)
    assert not ok and cleanup_env.wt("alpha").is_dir() and branch_exists(cleanup_env, "alpha")
    assert cleanup_env.remote_branches("alpha") == [b]


def test_stale_tracking_ref_deleted_only_after_ls_remote_shows_gone(cleanup_env):
    item = cleanup_env.merged_leftover("alpha", remote=True)
    b = branch_for(VERSION)
    tracking = f"refs/remotes/origin/{b}"
    tip = cleanup_env.local_ref("alpha", tracking)
    assert tip == item.remote_head
    _git(cleanup_env.bares["alpha"], "update-ref", "-d", f"refs/heads/{b}")   # deleted on merge; tracking ref stays
    ok, _ = execute(cleanup_env.ctx, item)
    calls = cleanup_env.git_calls()
    assert ok and cleanup_env.local_ref("alpha", tracking) is None
    assert ("update-ref", "-d", tracking, tip) in subargs(calls)
    last_ls = max(i for i, c in enumerate(calls) if c[:1] == ("ls-remote",))
    assert last_ls < index_of(calls, "update-ref", "-d", tracking)
    assert calls[last_ls] == ("ls-remote", "https://github.com/owner/alpha", f"refs/heads/{b}")


def test_successful_remote_delete_leaves_no_tracking_ref(cleanup_env):
    item = cleanup_env.merged_leftover("alpha", remote=True)
    tracking = f"refs/remotes/origin/{branch_for(VERSION)}"
    assert cleanup_env.local_ref("alpha", tracking) == item.remote_head
    assert execute(cleanup_env.ctx, item)[0]
    assert cleanup_env.local_ref("alpha", tracking) is None
    assert not [c for c in cleanup_env.git_calls() if c[:2] == ("update-ref", "-d") and tracking in c]


def test_tracking_ref_survives_when_the_remote_branch_is_kept(cleanup_env):
    item = cleanup_env.merged_leftover("alpha", remote=True)
    b = branch_for(VERSION)
    cleanup_env.hook("alpha", "exit 1")
    ok, _ = execute(cleanup_env.ctx, item)
    assert not ok and cleanup_env.local_ref("alpha", f"refs/remotes/origin/{b}") == item.remote_head
    assert not [c for c in cleanup_env.git_calls() if c[:2] == ("update-ref", "-d")]


# -- collect ---------------------------------------------------------------------------------------------


def test_foreign_names_untouched(cleanup_env):
    cleanup_env.make_branch("alpha", "chore/agent-ratchet-migrate-imports")
    cleanup_env.make_branch("alpha", "chore/agent-ratchet-4.0")
    cleanup_env.make_branch("alpha", "chore/agent-ratchet-4.0.1-rc1")
    cleanup_env.make_worktree("alpha", "alpha-wt-baseline-lowering", "fix/baseline")
    assert collect(cleanup_env.ctx, cleanup_env.consumer("alpha"), version=None, remote=True) == []


def test_fleet_named_branch_checked_out_in_a_foreign_worktree_is_kept(cleanup_env):
    cleanup_env.make_worktree("alpha", "alpha-wt-somewhere-else", branch_for(VERSION))
    item = cleanup_env.item("alpha")
    assert item.worktree is None
    ok, line = execute(cleanup_env.ctx, item)
    assert not ok and "worktree" in line and branch_exists(cleanup_env, "alpha")


def test_collect_filters_by_version_and_lists_worktrees_and_branches(cleanup_env):
    cleanup_env.merged_leftover("alpha", "4.0.1")
    cleanup_env.make_branch("alpha", branch_for("4.0.2"))
    consumer = cleanup_env.consumer("alpha")
    everything = collect(cleanup_env.ctx, consumer, version=None, remote=False)
    assert sorted(i.version for i in everything) == ["4.0.1", "4.0.2"]
    only = collect(cleanup_env.ctx, consumer, version="4.0.2", remote=False)
    assert [i.version for i in only] == ["4.0.2"] and only[0].worktree is None and only[0].local_head
    first = next(i for i in everything if i.version == "4.0.1")
    assert first.worktree is not None and Path(first.worktree).name == "alpha-wt-agent-ratchet-4.0.1"


# -- landed and the command ------------------------------------------------------------------------------


def test_cleanup_landed_deletes_remote_branch_first(cleanup_env):
    cleanup_env.merged_leftover("alpha", "4.0.1", remote=True)
    other = cleanup_env.merged_leftover("alpha", "4.0.2", remote=True)   # a later version stays untouched
    lines = cleanup_landed(cleanup_env.ctx, cleanup_env.consumer("alpha"), "4.0.1")
    calls = cleanup_env.git_calls()
    assert index_of(calls, "push", "--force-with-lease=refs/heads/chore/agent-ratchet-4.0.1") < \
        index_of(calls, "worktree", "remove")
    assert len(lines) == 1 and "4.0.1" in lines[0]
    assert cleanup_env.remote_branches("alpha") == [branch_for("4.0.2")]
    assert branch_exists(cleanup_env, "alpha", "4.0.2") and other.worktree.is_dir()
    assert cleanup_env.confirm.reasons == []   # no extra confirmation under the land approval


def test_run_cleanup_asks_once_and_prunes_tag_dirs(cleanup_env):
    cleanup_env.merged_leftover("alpha", "4.0.1")
    cleanup_env.merged_leftover("beta", "4.0.1", node_modules=True)
    cleanup_env.leftover("beta", "4.0.2", foreign=True)   # unsafe: reported, never touched
    state = cleanup_env.deps.dirs.state
    for minor in range(7):
        (state / f"v4.0.{minor}").mkdir(parents=True)
    code = run_cleanup(cleanup_env.deps, cleanup_env.cfg, None, remote=False)
    assert code == FleetExit.OK
    assert cleanup_env.confirm.reasons == ["cleanup 2 items"]
    assert not cleanup_env.wt("alpha").exists() and not cleanup_env.wt("beta").exists()
    assert cleanup_env.wt("beta", "4.0.2").is_dir() and branch_exists(cleanup_env, "beta", "4.0.2")
    assert sorted(p.name for p in state.glob("v4.*")) == [f"v4.0.{m}" for m in range(2, 7)]
    printed = cleanup_env.deps.out.getvalue()
    assert "merged into" in printed and "README" in printed


def test_run_cleanup_with_nothing_safe_asks_nothing(cleanup_env):
    cleanup_env.leftover("alpha", foreign=True)
    assert run_cleanup(cleanup_env.deps, cleanup_env.cfg, None, remote=False) == FleetExit.OK
    assert cleanup_env.confirm.reasons == []
    assert branch_exists(cleanup_env, "alpha") and "README" in cleanup_env.deps.out.getvalue()


def test_run_cleanup_with_no_items_is_ok_without_confirmation(cleanup_env):
    assert run_cleanup(cleanup_env.deps, cleanup_env.cfg, None, remote=True) == FleetExit.OK
    assert cleanup_env.confirm.reasons == []


def test_run_cleanup_filters_by_tag(cleanup_env):
    cleanup_env.merged_leftover("alpha", "4.0.1")
    cleanup_env.merged_leftover("alpha", "4.0.2")
    assert run_cleanup(cleanup_env.deps, cleanup_env.cfg, "v4.0.2", remote=False) == FleetExit.OK
    assert branch_exists(cleanup_env, "alpha", "4.0.1") and not branch_exists(cleanup_env, "alpha", "4.0.2")
    assert cleanup_env.confirm.reasons == ["cleanup 1 items"]


def test_run_cleanup_remote_deletes_remote_only_branches(cleanup_env):
    cleanup_env.remote_only("beta", "4.0.3", merged=True)
    assert run_cleanup(cleanup_env.deps, cleanup_env.cfg, None, remote=True) == FleetExit.OK
    assert cleanup_env.remote_branches("beta") == []
    assert cleanup_env.confirm.reasons == ["cleanup 1 items"]


def test_run_cleanup_kept_item_blocks(cleanup_env):
    cleanup_env.merged_leftover("alpha", remote=True)
    cleanup_env.hook("alpha", 'echo "hook says no" >&2\nexit 1')
    code = run_cleanup(cleanup_env.deps, cleanup_env.cfg, None, remote=True)
    assert code == FleetExit.BLOCKED
    assert "hook says no" in cleanup_env.deps.out.getvalue()
    assert cleanup_env.remote_branches("alpha") == [branch_for(VERSION)]


def test_run_cleanup_agent_markers_extend_the_reason(tmp_path, fleet_home):
    env = CleanupEnv(tmp_path, fleet_home, environ_extra={"CLAUDECODE": "1"})
    env.merged_leftover("alpha")
    assert run_cleanup(env.deps, env.cfg, None, remote=False) == FleetExit.OK
    assert env.confirm.reasons == ["cleanup 1 items" + AGENT_SUFFIX]


def test_run_cleanup_busy_lock_is_a_usage_error(cleanup_env):
    cleanup_env.merged_leftover("alpha")
    holder = RunLock(cleanup_env.deps.dirs.run_lock)
    assert holder.acquire(exclusive=True)
    try:
        with pytest.raises(UsageError):
            run_cleanup(cleanup_env.deps, cleanup_env.cfg, None, remote=False)
    finally:
        holder.release()
    assert branch_exists(cleanup_env, "alpha")


def test_run_cleanup_rejects_a_malformed_tag_before_any_git_call(cleanup_env):
    before = len(cleanup_env.deps.run.calls)
    with pytest.raises(UsageError):
        run_cleanup(cleanup_env.deps, cleanup_env.cfg, "4.0.1; rm", remote=False)
    assert len(cleanup_env.deps.run.calls) == before


def test_rev_parse_helper_sees_no_branch_after_cleanup(cleanup_env):
    item = cleanup_env.merged_leftover("alpha")
    assert execute(cleanup_env.ctx, item)[0]
    assert rev_parse(cleanup_env.git, cleanup_env.clones["alpha"], f"refs/heads/{branch_for(VERSION)}") is None
