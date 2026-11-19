"""APIs announced for removal in 3.x are gone in 4.0: guard_core is a tombstone, removed names raise AttributeError."""

from __future__ import annotations

import importlib
import os
from pathlib import Path
import subprocess
import sys
import tomllib
import warnings

import pytest

from agent_ratchet import cli, git_guard_io, lock_policy, migrate, refactoring_guard, version

ROOT = Path(__file__).resolve().parent.parent
SRC = str(ROOT / "src")
TOMBSTONE = "guard_core was removed in agent-ratchet 4.0; import agent_ratchet instead (see 'agent-ratchet migrate-imports')"
PYPROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "PYTHONPATH": SRC}
    return subprocess.run([sys.executable, *args], capture_output=True, text=True, env=env, check=False)


@pytest.mark.parametrize("stmt", ["import guard_core", "import guard_core.version", "from guard_core.git_guard_io import RULES_VERSION"])
def test_guard_core_import_is_a_tombstone(stmt: str) -> None:
    r = _run("-c", stmt)
    assert r.returncode != 0 and "ModuleNotFoundError" in r.stderr and TOMBSTONE in r.stderr


def test_tombstone_error_names_the_module() -> None:
    code = "try:\n import guard_core\nexcept ModuleNotFoundError as e:\n print(e.name)"
    assert _run("-c", code).stdout.strip() == "guard_core"


def test_python_dash_m_guard_core_fails_with_tombstone() -> None:
    r = _run("-m", "guard_core", "version")
    assert r.returncode != 0 and TOMBSTONE in r.stderr


def test_no_alias_finder_left_after_failed_import() -> None:
    code = "import sys\ntry:\n import guard_core\nexcept ModuleNotFoundError: pass\nprint(any(type(f).__module__.startswith('guard_core') for f in sys.meta_path))"
    assert _run("-c", code).stdout.strip() == "False"


@pytest.mark.parametrize(("module", "name"), [
    ("version", "GUARD_VERSION"), ("git_guard_io", "GUARD_VERSION"), ("refactoring_guard", "GUARD_VERSION"),
    ("git_guard_io", "SELF_SKIP_NAMES"), ("lock_policy", "RELEASE_TAG_PATTERN"),
])
def test_removed_attribute_raises_without_warning(module: str, name: str) -> None:
    mod = importlib.import_module(f"agent_ratchet.{module}")
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        with pytest.raises(AttributeError):
            getattr(mod, name)


def test_unknown_attribute_still_raises_attribute_error() -> None:
    for module in (version, git_guard_io, lock_policy, refactoring_guard):
        with pytest.raises(AttributeError, match="has no attribute 'NOPE'"):
            getattr(module, "NOPE")


def test_kept_names_do_not_warn() -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        assert version.VERSION
        assert git_guard_io.RULES_VERSION == "2.3.3"
        assert refactoring_guard.RULES_VERSION == "2.3.3"
        assert lock_policy.RELEASE_TAG_PATTERNS


def test_refactoring_guard_all_has_no_guard_version() -> None:
    assert "GUARD_VERSION" not in refactoring_guard.__all__


def test_only_agent_ratchet_script() -> None:
    assert PYPROJECT["project"]["scripts"] == {"agent-ratchet": "agent_ratchet.cli:main"}
    assert not hasattr(cli, "legacy_main")


def test_package_version_is_4_1_0() -> None:
    assert version.VERSION == "4.1.4" == PYPROJECT["project"]["version"]


def test_migrate_reports_guard_test_names_as_manual() -> None:
    assert "GUARD_TEST_NAMES" in migrate.MANUAL_NAMES


def test_wheel_packages_ship_the_tombstone() -> None:
    wheel = PYPROJECT["tool"]["hatch"]["build"]["targets"]["wheel"]
    assert "src/guard_core" in wheel["packages"]
