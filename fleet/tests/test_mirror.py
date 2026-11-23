from __future__ import annotations

import fcntl

import pytest
from fakes import make_deps, real_git
from repos import commit_files, make_bare, make_clone, make_upstream, push_all, redirect
from guard_fleet.exits import UsageError
from guard_fleet.git import object_type, rev_parse
from guard_fleet.mirror import MIRROR_REFSPECS, UPSTREAM_URL, mirror_readonly, refresh_mirror

A = {"src/agent_ratchet/a.py": b"x=1\n"}


def test_constants():
    assert UPSTREAM_URL == "https://github.com/dpopek/agent-ratchet"
    assert MIRROR_REFSPECS == ("+refs/heads/main:refs/heads/main", "+refs/tags/*:refs/tags/*")


def test_refresh_mirror_clones_then_fetches_tags(tmp_path, fleet_home):
    up = make_upstream(tmp_path, {"v4.0.0": A})
    redirect(fleet_home, UPSTREAM_URL, up)
    path = refresh_mirror(make_deps(fleet_home), real_git())
    assert object_type(real_git(), path, "v4.0.0") == "tag"
    assert real_git()(path, "config", "maintenance.auto").text.strip() == "false"
    assert real_git()(path, "config", "gc.auto").text.strip() == "0"
    stamp = (fleet_home / ".local/state/guard-fleet/mirror.fetched").read_text().strip()
    assert stamp == "2023-11-14T22:13:20+00:00"


def test_refresh_mirror_picks_up_new_tags_and_main(tmp_path, fleet_home):
    up = make_upstream(tmp_path, {"v4.0.0": A})
    redirect(fleet_home, UPSTREAM_URL, up)
    deps = make_deps(fleet_home)
    path = refresh_mirror(deps, real_git())
    work = make_clone(up, tmp_path / "w")
    new = commit_files(work, "v4.0.1", {"f": "1"})
    from repos import tag_annotated
    tag_annotated(work, "v4.0.1")
    push_all(work)
    refresh_mirror(deps, real_git())
    assert object_type(real_git(), path, "v4.0.1") == "tag"
    assert rev_parse(real_git(), path, "main") == new


def test_refresh_mirror_busy_lock_times_out(tmp_path, fleet_home):
    deps = make_deps(fleet_home)
    deps.dirs.state.mkdir(parents=True)
    with open(deps.dirs.mirror_lock, "wb") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        with pytest.raises(UsageError, match="mirror lock busy"):
            refresh_mirror(deps, real_git())
    assert deps.clock.monotonic() - 1000.0 >= 60


def test_mirror_readonly_requires_a_mirror(fleet_home):
    with pytest.raises(UsageError, match="no mirror yet; run guard-fleet plan once without a busy lock"):
        mirror_readonly(make_deps(fleet_home))


def test_mirror_readonly_returns_path_and_timestamp(tmp_path, fleet_home):
    up = make_upstream(tmp_path, {"v4.0.0": A})
    redirect(fleet_home, UPSTREAM_URL, up)
    deps = make_deps(fleet_home)
    path = refresh_mirror(deps, real_git())
    assert mirror_readonly(deps) == (path, "2023-11-14T22:13:20+00:00")


def test_mirror_readonly_without_timestamp_is_usage_error(tmp_path, fleet_home):
    deps = make_deps(fleet_home)
    deps.dirs.mirror.mkdir(parents=True)
    with pytest.raises(UsageError):
        mirror_readonly(deps)


def test_make_upstream_one_commit_per_tag_in_order(tmp_path):
    up = make_upstream(tmp_path, {"v1": {"f": b"1"}, "v2": {"f": b"2"}})
    g = real_git()
    assert object_type(g, up, "v1") == "tag" and object_type(g, up, "v2") == "tag"
    assert g(up, "rev-list", "--count", "main").text.strip() == "2"
    assert g(up, "show", "v1:f").stdout == b"1" and g(up, "show", "v2:f").stdout == b"2"


def test_make_upstream_lightweight_and_side_branch_tags(tmp_path):
    up = make_upstream(tmp_path, {"v1": {"f": b"1"}, "v2": {"f": b"2"}},
                       lightweight_tags={"lw": "v1"}, side_branch_tags={"sb": "side commit"})
    g = real_git()
    assert object_type(g, up, "lw") == "commit"
    assert rev_parse(g, up, "lw") == rev_parse(g, up, "v1^{commit}")
    assert g(up, "log", "-1", "--format=%s", "sb").text.strip() == "side commit"
    assert g(up, "merge-base", "--is-ancestor", "sb^{commit}", "main", check=False).rc == 1
    assert g(up, "rev-parse", "--verify", "side").rc == 0
