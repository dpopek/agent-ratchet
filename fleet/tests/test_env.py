from pathlib import Path

import pytest

from guard_fleet.env import (
    AGENT_MARKERS, agent_markers_present, base_child_env, commit_env, forbidden_env_key,
    g6_env, refusal_lines, take_lock_update_flag)
from guard_fleet.exits import UsageError


def test_child_env_strips_hook_skip_vars(tmp_path):
    src = {"PATH": f"{tmp_path}/tool/bin:/usr/bin", "HUSKY": "0", "SKIP": "gitleaks",
           "GLOBAL_PRE_COMMIT_ACTIVE": "1", "PRE_COMMIT_ALLOW_NO_CONFIG": "1", "LEFTHOOK": "0",
           "GIT_DIR": "/x", "GH_REPO": "o/r", "VIRTUAL_ENV": "/v", "ALLOW_ASSERTION_REDUCTION": "1", "HOME": "/h"}
    out = base_child_env(src, tool_bin=tmp_path / "tool/bin")
    assert out == {"PATH": "/usr/bin", "HOME": "/h", "GIT_TERMINAL_PROMPT": "0", "GH_PROMPT_DISABLED": "1"}


def test_child_env_strips_git_config_nosystem(tmp_path):
    out = base_child_env({"PATH": "/usr/bin", "GIT_CONFIG_NOSYSTEM": "1"}, tool_bin=tmp_path)
    assert "GIT_CONFIG_NOSYSTEM" not in out


def test_child_env_without_path(tmp_path):
    out = base_child_env({"HOME": "/h"}, tool_bin=tmp_path)
    assert "PATH" not in out and out["HOME"] == "/h"


def test_forbidden_env_key():
    for k in ("GIT_DIR", "GLOBAL_X", "HUSKY", "HUSKY_SKIP_HOOKS", "SKIP", "PRE_COMMIT_HOME",
              "LEFTHOOK", "ALLOW_GUARD_LOCK_UPDATE"):
        assert forbidden_env_key(k)
    for k in ("PATH", "HOME", "GH_REPO", "X_PY"):
        assert not forbidden_env_key(k)


def test_commit_env_adds_lock_flag_only_when_asked():
    base = {"PATH": "/usr/bin"}
    assert "ALLOW_GUARD_LOCK_UPDATE" not in commit_env(base, {}, lock_update=False)
    assert commit_env(base, {"X_PY": "/p"}, lock_update=True)["ALLOW_GUARD_LOCK_UPDATE"] == "1"
    assert commit_env(base, {"X_PY": "/p"}, lock_update=True)["X_PY"] == "/p"
    with pytest.raises(UsageError):
        commit_env(base, {"HUSKY": "0"}, lock_update=False)
    with pytest.raises(UsageError):
        commit_env(base, {"ALLOW_GUARD_LOCK_UPDATE": "1"}, lock_update=False)


def test_take_lock_update_flag_pops_and_needs_exact_one():
    e = {"ALLOW_GUARD_LOCK_UPDATE": "true"}
    assert take_lock_update_flag(e) is False and "ALLOW_GUARD_LOCK_UPDATE" not in e
    assert take_lock_update_flag({"ALLOW_GUARD_LOCK_UPDATE": "1"}) is True
    assert take_lock_update_flag({}) is False


def test_agent_markers_present():
    assert agent_markers_present({}) is False
    assert agent_markers_present({"CLAUDECODE": ""}) is False
    for m in AGENT_MARKERS:
        assert agent_markers_present({m: "1"}) is True


def test_refusal_without_markers_prints_ready_command():
    assert refusal_lines("guard-fleet release v4.4.1 --hold-ring-2", markers=False) == [
        "Run: ALLOW_GUARD_LOCK_UPDATE=1 guard-fleet release v4.4.1 --hold-ring-2"]


def test_refusal_with_markers_has_no_ready_line():
    lines = refusal_lines("guard-fleet release v4.4.1 --hold-ring-2", markers=True)
    assert lines == ["Run in your own terminal: guard-fleet release v4.4.1 --hold-ring-2",
                     "It needs ALLOW_GUARD_LOCK_UPDATE=1 set by you, not by an agent."]
    assert not any(l.lstrip().startswith(("Run: ALLOW", "ALLOW_")) for l in lines)


def test_g6_env_isolates_home_and_git_config(tmp_path):
    out = g6_env({"PATH": "/usr/bin", "HOME": "/h"}, tmp_path, uv_cache=Path("/c"))
    assert out["HOME"] == str(tmp_path / "home")
    for k in ("XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME"):
        assert out[k].startswith(str(tmp_path))
        assert Path(out[k]).is_dir()
    assert Path(out["HOME"]).is_dir()
    assert out["GIT_CONFIG_GLOBAL"] == "/dev/null" and out["GIT_CONFIG_NOSYSTEM"] == "1"
    assert out["PYTHONDONTWRITEBYTECODE"] == "1" and out["UV_CACHE_DIR"] == "/c"
    assert out["PATH"] == "/usr/bin"
