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
