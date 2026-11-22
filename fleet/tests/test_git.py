from __future__ import annotations

import pytest
from fakes import FakeRunner, Route, real_git
from repos import commit_files, make_bare, make_clone, make_clone_from_url, push_all, redirect
from guard_fleet.git import (GIT_SAFE, Git, GitError, GitLockError, GitNetworkError, diff_name_status,
                             fetch_default, has_commit, is_ancestor, ls_remote, object_type, origin_url,
                             rev_parse, show_bytes, status_porcelain)


def fake(routes):
    return Git(FakeRunner(routes, real=frozenset()), {}, lambda s: None)


def test_git_adds_safe_flags(fake_deps, tmp_path):
    runner = FakeRunner([Route(("git",), stdout=b"ok")], real=frozenset())
    Git(runner, {}, lambda s: None)(tmp_path, "status")
    assert runner.calls[0][0][:5] == ("git", "-c", "maintenance.auto=false", "-c", "gc.auto=0")
    assert GIT_SAFE == ("-c", "maintenance.auto=false", "-c", "gc.auto=0")
    assert runner.calls[0][1] == tmp_path


def test_is_ancestor_rc_mapping(tmp_path):
    ok = lambda rc: is_ancestor(fake([Route(("git",), rc=rc, stderr=b"fatal")]), tmp_path, "a", "b")  # noqa: E731
    assert ok(0) is True and ok(1) is False
    with pytest.raises(GitError):
        ok(128)


def test_is_ancestor_raises_on_other_rc(tmp_path):
    runner = FakeRunner([Route(("git",), rc=128, stderr=b"fatal")], real=frozenset())
    with pytest.raises(GitError):
        is_ancestor(Git(runner, {}, lambda s: None), tmp_path, "a", "b")


def test_check_false_returns_result(tmp_path):
    r = fake([Route(("git",), rc=3)])(tmp_path, "x", check=False)
    assert r.rc == 3


@pytest.mark.parametrize("stderr", [
    b"error: could not lock config file x.lock': File exists",
    b"fatal: Unable to create '/r/.git/index.lock': File exists.",
])
def test_lock_stderr_classified(tmp_path, stderr):
    with pytest.raises(GitLockError):
        fake([Route(("git",), rc=128, stderr=stderr)])(tmp_path, "commit")


@pytest.mark.parametrize("msg", ["Could not resolve host: x", "Failed to connect", "Connection timed out",
                                 "Operation timed out", "unable to access 'u'", "Connection reset by peer"])
def test_network_stderr_classified(tmp_path, msg):
    with pytest.raises(GitNetworkError):
        fake([Route(("git",), rc=128, stderr=msg.encode())])(tmp_path, "fetch")


def test_lock_file_is_git_lock_error(tmp_path):
    repo = make_clone(make_bare(tmp_path, "alpha"), tmp_path / "alpha")
    (repo / ".git/index.lock").write_bytes(b"")
    with pytest.raises(GitLockError):
        real_git()(repo, "commit", "--allow-empty", "-m", "x")


def test_ls_remote_retries_network_errors_then_gives_up(tmp_path):
    sleeps: list[float] = []
    runner = FakeRunner([Route(("git",), rc=128, stderr=b"Could not resolve host")], real=frozenset())
    git = Git(runner, {}, sleeps.append, backoff=(1, 2, 4))
    with pytest.raises(GitNetworkError):
        ls_remote(git, tmp_path, "u", "refs/heads/main")
    assert sleeps == [1, 2, 4] and len(runner.calls) == 4


def test_ls_remote_recovers_after_transient_failure(tmp_path):
    state = {"n": 0}

    def effect(argv, cwd, env):
        from guard_fleet.proc import Result
        state["n"] += 1
        if state["n"] == 1:
            return Result(argv, 128, b"", b"Connection reset", False)
        return Result(argv, 0, b"abc\trefs/heads/main\n", b"", False)

    runner = FakeRunner([Route(("git",), effect=effect)], real=frozenset())
    got = ls_remote(Git(runner, {}, lambda s: None), tmp_path, "u", "refs/heads/main")
    assert got == {"refs/heads/main": "abc"}


def test_ls_remote_real(tmp_path):
    bare = make_bare(tmp_path, "alpha")
    clone = make_clone(bare, tmp_path / "alpha")
    sha = commit_files(clone, "c1", {"f": "1"})
    push_all(clone)
    assert ls_remote(real_git(), tmp_path, str(bare), "refs/heads/main") == {"refs/heads/main": sha}
    assert ls_remote(real_git(), tmp_path, str(bare), "refs/heads/nope") == {}


def test_fetch_default_updates_no_ref(tmp_path):
    bare = make_bare(tmp_path, "alpha")
    clone = make_clone(bare, tmp_path / "alpha")
    before = real_git()(clone, "for-each-ref").stdout
    new = commit_files(make_clone(bare, tmp_path / "other"), "c2", {"f": "2"})
    push_all(tmp_path / "other")
    fetch_default(real_git(), clone, "main")
    assert real_git()(clone, "for-each-ref").stdout == before and has_commit(real_git(), clone, new)


def test_fetch_default_exact_argv_and_retry(tmp_path):
    sleeps: list[float] = []
    runner = FakeRunner([Route(("git",), rc=128, stderr=b"unable to access")], real=frozenset())
    with pytest.raises(GitNetworkError):
        fetch_default(Git(runner, {}, sleeps.append), tmp_path, "main")
    assert runner.calls[0][0][len(GIT_SAFE) + 1:] == (
        "fetch", "--no-tags", "--no-write-fetch-head", "--refmap=", "origin", "refs/heads/main")
    assert sleeps == [1, 2, 4]


def test_origin_url_is_raw_not_insteadof_expanded(tmp_path, fleet_home):
    bare = make_bare(tmp_path, "alpha")
    redirect(fleet_home, "https://example.com/owner/alpha", bare)
    clone = make_clone_from_url("https://example.com/owner/alpha", tmp_path / "c")
    assert origin_url(real_git(), clone) == "https://example.com/owner/alpha"
    assert real_git()(clone, "remote", "get-url", "origin").text.strip().startswith("file://")


def test_origin_url_none_without_remote(tmp_path):
    real_git()(tmp_path, "init", "-q")
    assert origin_url(real_git(), tmp_path) is None


def test_rev_parse_object_type_has_commit_show_bytes(tmp_path):
    bare = make_bare(tmp_path, "alpha")
    clone = make_clone(bare, tmp_path / "alpha")
    sha = commit_files(clone, "c1", {"d/f.bin": b"\x00\xff"})
    g = real_git()
    assert rev_parse(g, clone, "HEAD") == sha and rev_parse(g, clone, "nope") is None
    assert object_type(g, clone, "HEAD") == "commit" and object_type(g, clone, "nope") is None
    assert has_commit(g, clone, sha) and not has_commit(g, clone, "0" * 40)
    assert show_bytes(g, clone, "HEAD", "d/f.bin") == b"\x00\xff"
    assert show_bytes(g, clone, "HEAD", "missing") is None


def test_is_ancestor_real(tmp_path):
    clone = make_clone(make_bare(tmp_path, "alpha"), tmp_path / "alpha")
    a = commit_files(clone, "c1", {"f": "1"})
    b = commit_files(clone, "c2", {"f": "2"})
    g = real_git()
    assert is_ancestor(g, clone, a, b) is True and is_ancestor(g, clone, b, a) is False


def test_diff_name_status_and_status_porcelain(tmp_path):
    clone = make_clone(make_bare(tmp_path, "alpha"), tmp_path / "alpha")
    a = commit_files(clone, "c1", {"keep": "1", "gone": "1", "mod": "1"})
    b = commit_files(clone, "c2", {"new file": "1", "gone": None, "mod": "2"})
    g = real_git()
    assert sorted(diff_name_status(g, clone, a, b)) == [("A", "new file"), ("D", "gone"), ("M", "mod")]
    (clone / "u.txt").write_text("x")
    (clone / ".gitignore").write_text("ign\n")
    (clone / "ign").write_text("x")
    plain = status_porcelain(g, clone)
    assert "?? u.txt" in plain and not any(e.endswith("ign") for e in plain)
    assert any(e.endswith("ign") for e in status_porcelain(g, clone, ignored=True))
