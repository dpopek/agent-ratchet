from __future__ import annotations

import io
import json
import os
from types import SimpleNamespace

import pytest

from fakes import FakeConfirm, make_deps, real_git
from guard_fleet import selfcheck
from guard_fleet.exits import Cancelled, FleetExit, ShaMismatch, UsageError
from guard_fleet.locks import RunLock
from guard_fleet.selfcheck import SelfCheckError, check_expect_sha, installed_sha, self_check
from guard_fleet.selfpin import run_self_pin
from guard_fleet.target import TargetError
from repos import _git, commit_files, make_clone, sha_of


def test_untagged_running_sha_is_exit_2(upstream_mirror):
    git, mirror = upstream_mirror
    with pytest.raises(SelfCheckError, match="no v4 tag peels to " + "d" * 40):
        self_check(git, mirror, "d" * 40, target_sha=None)


def test_running_tag_is_returned(upstream_mirror):
    git, mirror = upstream_mirror
    assert self_check(git, mirror, sha_of(mirror, "v4.1.0"), target_sha=None) == "v4.1.0"
    assert self_check(git, mirror, sha_of(mirror, "v4.1.0"), target_sha=sha_of(mirror, "v4.0.0")) == "v4.1.0"


def test_running_equal_to_target_is_exit_2(upstream_mirror):
    git, mirror = upstream_mirror
    t = sha_of(mirror, "v4.1.0")
    with pytest.raises(SelfCheckError, match="running fleet equals the target"):
        self_check(git, mirror, t, target_sha=t)


def test_side_branch_tag_fails_reachability(upstream_mirror):
    git, mirror = upstream_mirror
    with pytest.raises(SelfCheckError, match="not reachable from main"):
        self_check(git, mirror, sha_of(mirror, "v4.8.0"), target_sha=None)


def test_lightweight_tag_is_not_a_release_tag(upstream_mirror):
    git, mirror = upstream_mirror
    # v4.9.0 is lightweight on the same commit as v4.1.0; the annotated tag still wins
    assert self_check(git, mirror, sha_of(mirror, "v4.9.0"), target_sha=None) == "v4.1.0"


def test_remote_peel_mismatch_fails(upstream_mirror, upstream_bare, tmp_path):
    git, mirror = upstream_mirror
    work = make_clone(upstream_bare, tmp_path / "rewrite")
    commit_files(work, "moved", {"f": "2"})
    _git(work, "tag", "-f", "-a", "v4.1.0", "-m", "moved")
    _git(work, "push", "-q", "--force", "origin", "main", "refs/tags/v4.1.0")
    with pytest.raises(SelfCheckError, match="ls-remote peel differs"):
        self_check(git, mirror, sha_of(mirror, "v4.1.0"), target_sha=None)


def test_expect_sha_mismatch_is_exit_3():
    with pytest.raises(ShaMismatch):
        check_expect_sha("a" * 40, "b" * 40)
    with pytest.raises(ShaMismatch):
        check_expect_sha("a" * 40, None)
    with pytest.raises(UsageError):
        check_expect_sha("A" * 40, "a" * 40)
    with pytest.raises(UsageError):
        check_expect_sha("a" * 39, "a" * 39)
    check_expect_sha("a" * 40, "a" * 40)


def test_sha_mismatch_is_not_a_usage_error():
    assert not issubclass(ShaMismatch, UsageError)


class _Dist:
    def __init__(self, raw):
        self.raw = raw

    def read_text(self, name):
        assert name == "direct_url.json"
        return self.raw


@pytest.mark.parametrize("raw, expected", [
    (json.dumps({"vcs_info": {"commit_id": "a" * 40}}), "a" * 40),
    (json.dumps({"vcs_info": {"commit_id": "A" * 40}}), None),
    (json.dumps({"vcs_info": {"commit_id": "a" * 39}}), None),
    (json.dumps({"vcs_info": {"commit_id": 5}}), None),
    (json.dumps({"url": "file:///x"}), None),
    (json.dumps([1]), None),
    ("not json", None),
    ("", None),
    (None, None),
])
def test_installed_sha_reads_pep610(monkeypatch, raw, expected):
    monkeypatch.setattr(selfcheck.importlib.metadata, "distribution", lambda name: _Dist(raw))
    assert installed_sha() == expected


def test_installed_sha_missing_distribution_is_none():
    assert installed_sha("no-such-distribution-alpha") is None


@pytest.fixture
def selfpin_env(upstream_bare, fake_deps, fleet_home):
    confirm = FakeConfirm(["approved"])
    deps = make_deps(fleet_home, confirm=confirm, environ=fake_deps.environ)
    deps.out = io.StringIO()
    return SimpleNamespace(deps=deps, git=real_git(), confirm=confirm, lock=deps.dirs.self_lock)


def test_self_pin_writes_atomically_after_confirmation(selfpin_env, upstream_bare):
    e = selfpin_env
    t = sha_of(upstream_bare, "v4.1.0")
    assert run_self_pin(e.deps, e.git, "v4.1.0") == FleetExit.OK
    assert e.lock.read_text() == t + "\n"
    assert e.lock.stat().st_mode & 0o777 == 0o644
    assert sorted(p.name for p in e.lock.parent.iterdir()) == ["self.lock"]  # no temp file left
    out = e.deps.out.getvalue()
    assert "missing" in out and "v4.1.0" in out and t in out
    assert e.confirm.reasons == [f"self-pin v4.1.0 ({t[:7]})"]
    # second pin shows the previous content
    e.confirm._results.append("approved")
    run_self_pin(e.deps, e.git, "v4.0.0")
    assert t in e.deps.out.getvalue().split("v4.0.0")[0].split("missing", 1)[1]
    assert e.lock.read_text() == sha_of(upstream_bare, "v4.0.0") + "\n"


def test_self_pin_cancelled_leaves_lock_unchanged(selfpin_env):
    e = selfpin_env
    e.lock.parent.mkdir(parents=True)
    e.lock.write_text("c" * 40 + "\n")
    e.confirm._results[:] = ["cancelled"]
    with pytest.raises(Cancelled):
        run_self_pin(e.deps, e.git, "v4.1.0")
    assert e.lock.read_text() == "c" * 40 + "\n"
    assert [p.name for p in e.lock.parent.iterdir()] == ["self.lock"]


def test_self_pin_rejects_invalid_target_before_writing(selfpin_env):
    e = selfpin_env
    with pytest.raises(TargetError, match="not annotated"):
        run_self_pin(e.deps, e.git, "v4.9.0")
    assert not e.lock.exists()
    assert e.confirm.reasons == []


def test_self_pin_busy_lock_is_usage_error(selfpin_env):
    e = selfpin_env
    held = RunLock(e.deps.dirs.run_lock)
    assert held.acquire(exclusive=True)
    try:
        with pytest.raises(UsageError, match="lock busy"):
            run_self_pin(e.deps, e.git, "v4.1.0")
    finally:
        held.release()
    assert not e.lock.exists()


def test_self_pin_releases_the_run_lock(selfpin_env):
    e = selfpin_env
    run_self_pin(e.deps, e.git, "v4.1.0")
    again = RunLock(e.deps.dirs.run_lock)
    assert again.acquire(exclusive=True)
    again.release()


def test_self_pin_removes_temp_file_when_replace_fails(selfpin_env, monkeypatch):
    e = selfpin_env

    def boom(src, dst):
        raise OSError("replace failed")

    monkeypatch.setattr("guard_fleet.selfpin.os.replace", boom)
    with pytest.raises(OSError):
        run_self_pin(e.deps, e.git, "v4.1.0")
    assert list(e.lock.parent.iterdir()) == []


def test_self_pin_fsyncs_the_config_directory(selfpin_env, monkeypatch):
    e = selfpin_env
    synced = []
    real = os.fsync

    def spy(fd):
        synced.append(os.path.isdir(f"/dev/fd/{fd}"))
        real(fd)

    monkeypatch.setattr("guard_fleet.selfpin.os.fsync", spy)
    run_self_pin(e.deps, e.git, "v4.1.0")
    assert synced == [False, True]  # the temp file, then the directory
