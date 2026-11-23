"""Shared fixtures: every test runs with a private HOME and no agent markers."""

from __future__ import annotations

import io
import os
from pathlib import Path

import pytest

from guard_fleet.env import base_child_env

AGENT_MARKERS = ("CLAUDECODE", "AI_AGENT", "CODEX_THREAD_ID", "CODEX_SHELL", "ANTIGRAVITY_AGENT")


@pytest.fixture(autouse=True)
def fleet_home(tmp_path, monkeypatch):
    for key in AGENT_MARKERS:
        monkeypatch.delenv(key, raising=False)
    home = tmp_path / "home"
    home.mkdir()
    (home / ".gitconfig").write_text(
        "[user]\n\tname = Fleet Test\n\temail = test@example.com\n[init]\n\tdefaultBranch = main\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("HOME", str(home))
    return home


@pytest.fixture
def fake_deps(fleet_home):
    """Deps with a clean env (HOME = the tmp home), a FakeRunner and fake clock/sleep."""
    from fakes import make_deps

    environ = base_child_env(os.environ, tool_bin=Path("/nonexistent"))
    environ["HOME"] = str(fleet_home)
    return make_deps(fleet_home, environ=environ)


@pytest.fixture
def upstream_bare(tmp_path, fleet_home):
    """A local upstream: v4.0.0 and v4.1.0 annotated on main, v4.9.0 lightweight, v4.8.0 on a side branch forked from v4.0.0."""
    from guard_fleet.mirror import UPSTREAM_URL
    from repos import _git, commit_files, make_clone, make_upstream, push_all, redirect, tag_annotated

    bare = make_upstream(
        tmp_path / "up",
        {"v4.0.0": {"f": b"0"}, "v4.1.0": {"f": b"1"}},
        lightweight_tags={"v4.9.0": "v4.1.0"},
    )
    work = make_clone(bare, tmp_path / "side-work")  # v4.8.0 forks off v4.0.0, so it diverges from v4.1.0
    _git(work, "checkout", "-q", "-b", "side", "v4.0.0")
    commit_files(work, "side work", {"s": "1"})
    tag_annotated(work, "v4.8.0")
    push_all(work)
    redirect(fleet_home, UPSTREAM_URL, bare)
    return bare


@pytest.fixture
def upstream_mirror(upstream_bare, fake_deps):
    from fakes import real_git
    from guard_fleet.mirror import refresh_mirror

    git = real_git()
    return git, refresh_mirror(fake_deps, git)
