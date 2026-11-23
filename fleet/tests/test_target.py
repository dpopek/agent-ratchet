from __future__ import annotations

from pathlib import Path

import pytest

from fakes import FakeRunner
from guard_fleet.git import Git
from guard_fleet.target import (RELEASE_TAG_RE, Target, TargetError, check_tag_syntax, newest_v4_tag,
                                pin_relation, release_tag_for, validate_target)
from repos import _git, commit_files, make_clone, push_all, sha_of, tag_annotated


@pytest.mark.parametrize("tag", ["v4.4.1\n", "v4.4.1 ", " v4.4.1", "V4.4.1", "v4.04.1", "v4.4.01",
                                 "v4.4.١", "v3.2.0", "v4.4", "v4.4.1.0", "v4.4.1-rc1"])
def test_tag_regex_rejects_newline_and_unicode_digits(tag):
    runner = FakeRunner([])
    with pytest.raises(TargetError):
        validate_target(Git(runner, {}, lambda s: None), Path("/nonexistent"), tag)
    assert runner.calls == []


def test_check_tag_syntax_returns_version():
    assert check_tag_syntax("v4.12.0") == (4, 12, 0)


def test_validate_target_rejects_lightweight_and_unreachable(upstream_mirror):
    git, mirror = upstream_mirror
    target = validate_target(git, mirror, "v4.1.0")
    assert target == Target("v4.1.0", sha_of(mirror, "v4.1.0"), (4, 1, 0))
    with pytest.raises(TargetError, match="not annotated"):
        validate_target(git, mirror, "v4.9.0")
    with pytest.raises(TargetError, match="not reachable from main"):
        validate_target(git, mirror, "v4.8.0")
    with pytest.raises(TargetError, match="does not exist"):
        validate_target(git, mirror, "v4.7.0")


def test_validate_target_rejects_remote_peel_mismatch(upstream_mirror, upstream_bare, tmp_path):
    git, mirror = upstream_mirror
    work = make_clone(upstream_bare, tmp_path / "rewrite")
    commit_files(work, "moved", {"f": "2"})
    _git(work, "tag", "-f", "-a", "v4.1.0", "-m", "moved")
    _git(work, "push", "-q", "--force", "origin", "main", "refs/tags/v4.1.0")
    with pytest.raises(TargetError, match="ls-remote peel differs"):
        validate_target(git, mirror, "v4.1.0")


def test_newest_v4_tag_skips_lightweight_and_side_branch(upstream_mirror):
    git, mirror = upstream_mirror
    assert newest_v4_tag(git, mirror).tag == "v4.1.0"


def test_newest_v4_tag_orders_numerically(upstream_mirror, upstream_bare, tmp_path):
    git, mirror = upstream_mirror
    work = make_clone(upstream_bare, tmp_path / "next")
    for tag in ("v4.2.0", "v4.10.0"):
        commit_files(work, tag, {"f": tag})
        tag_annotated(work, tag)
    push_all(work)
    _git(mirror, "fetch", "origin", "+refs/heads/main:refs/heads/main", "+refs/tags/*:refs/tags/*")
    assert newest_v4_tag(git, mirror).version == (4, 10, 0)


def test_pin_relation_and_release_tag_for(upstream_mirror):
    git, mirror = upstream_mirror
    p, t = sha_of(mirror, "v4.0.0"), sha_of(mirror, "v4.1.0")
    assert pin_relation(git, mirror, p, t) == "candidate"
    assert pin_relation(git, mirror, t, t) == "current"
    assert pin_relation(git, mirror, t, p) == "current"
    assert pin_relation(git, mirror, sha_of(mirror, "v4.8.0"), t) == "diverged"
    assert release_tag_for(git, mirror, p) == "v4.0.0"
    assert release_tag_for(git, mirror, sha_of(mirror, "v4.8.0")) == "v4.8.0"


def test_release_tag_for_lowest_version_and_ignores_lightweight(upstream_mirror):
    git, mirror = upstream_mirror
    t = sha_of(mirror, "v4.1.0")
    # v4.9.0 is a lightweight alias of v4.1.0 and must not count; add a lower annotated alias.
    _git(mirror, "tag", "-a", "v3.5.0", "-m", "alias", t)
    assert release_tag_for(git, mirror, t) == "v3.5.0"
    _git(mirror, "tag", "-d", "v3.5.0", "v4.1.0")
    assert release_tag_for(git, mirror, t) is None


def test_release_tag_re_matches_v3_and_v4_only():
    assert RELEASE_TAG_RE.match("v3.0.1") and RELEASE_TAG_RE.match("v4.10.0")
    assert not RELEASE_TAG_RE.match("v5.0.0") and not RELEASE_TAG_RE.match("v4.0.0\n")
