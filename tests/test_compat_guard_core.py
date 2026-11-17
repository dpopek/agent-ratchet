"""The guard_core compat package (kept until 4.0) aliases agent_ratchet module for module."""

from __future__ import annotations

import importlib
import os
from pathlib import Path
import subprocess
import sys
import tomllib

import pytest

from test_package_imports import MODULES

ROOT = Path(__file__).resolve().parents[1]


pytestmark = pytest.mark.filterwarnings("ignore:guard_core is deprecated:DeprecationWarning")


@pytest.mark.parametrize("name", [*MODULES, "cli", "lock_policy", "version"])
def test_old_module_path_is_the_new_module(name: str) -> None:
    assert importlib.import_module(f"guard_core.{name}") is importlib.import_module(f"agent_ratchet.{name}")


def test_aliased_module_keeps_its_own_spec() -> None:
    import guard_core.baseline_diff  # noqa: F401
    import agent_ratchet.baseline_diff as new

    assert new.__spec__.name == "agent_ratchet.baseline_diff"


def test_from_import_of_a_private_name_works() -> None:
    from guard_core.test_baseline_integrity import _is_ceiling_key
    from agent_ratchet.test_baseline_integrity import _is_ceiling_key as new

    assert _is_ceiling_key is new


def test_monkeypatch_through_the_old_path_is_seen_by_the_new(monkeypatch) -> None:
    import guard_core.version as old
    import agent_ratchet.version as new

    monkeypatch.setattr(old, "installed_sha", lambda: "x")
    assert new.installed_sha() == "x"


def test_unknown_submodule_still_raises() -> None:
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module("guard_core.no_such_module")


def test_python_dash_m_guard_core_runs_the_cli() -> None:
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
    old = subprocess.run([sys.executable, "-m", "guard_core", "version"], capture_output=True, text=True, env=env)
    new = subprocess.run([sys.executable, "-m", "agent_ratchet", "version"], capture_output=True, text=True, env=env)
    assert old.returncode == new.returncode == 0
    assert old.stdout == new.stdout


def test_both_console_scripts_share_one_entry_point() -> None:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert pyproject["project"]["scripts"] == {"agent-ratchet": "agent_ratchet.cli:main", "guard-core": "agent_ratchet.cli:legacy_main"}
    assert pyproject["tool"]["hatch"]["build"]["targets"]["wheel"]["packages"] == ["src/agent_ratchet", "src/guard_core"]
