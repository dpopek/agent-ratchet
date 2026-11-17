"""Every API removed in 4.0 warns when used; the replacements stay silent and the scan output is unchanged."""

from __future__ import annotations

import importlib
import os
from pathlib import Path
import re
import subprocess
import sys
import warnings

import pytest

from agent_ratchet import git_guard_io, lock_policy, refactoring_guard, version
from agent_ratchet.cli import legacy_main, main

SRC = str(Path(__file__).resolve().parent.parent / "src")
GUARD_CORE_MSG = "guard_core is deprecated and removed in 4.0; import agent_ratchet instead (see 'agent-ratchet migrate-imports')"
GUARD_CORE_SCRIPT_LINE = "agent-ratchet: 'guard-core' is deprecated and removed in 4.0; use 'agent-ratchet'"
GUARD_CORE_MODULE_LINE = "agent-ratchet: 'python -m guard_core' is deprecated and removed in 4.0; use 'python -m agent_ratchet'"
SELF_SKIP_MSG = "agent_ratchet.git_guard_io.SELF_SKIP_NAMES is deprecated and removed in 4.0; use is_self_skipped()"
TAG_MSG = "agent_ratchet.lock_policy.RELEASE_TAG_PATTERN is deprecated and removed in 4.0; use RELEASE_TAG_PATTERNS"


def _guard_version_msg(module: str, replacement: str) -> str:
    return f"agent_ratchet.{module}.GUARD_VERSION is deprecated and removed in 4.0; use agent_ratchet.{module}.{replacement}"


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "PYTHONPATH": SRC}
    return subprocess.run([sys.executable, *args], capture_output=True, text=True, env=env, check=False)


def test_import_guard_core_warns_in_fresh_process() -> None:
    result = _run("-W", "error::DeprecationWarning", "-c", "import guard_core.version")
    assert result.returncode != 0
    assert GUARD_CORE_MSG in result.stderr


@pytest.mark.parametrize(
    ("module", "name", "message", "replacement"),
    [
        (version, "GUARD_VERSION", _guard_version_msg("version", "VERSION"), "VERSION"),
        (git_guard_io, "GUARD_VERSION", _guard_version_msg("git_guard_io", "RULES_VERSION"), "RULES_VERSION"),
        (refactoring_guard, "GUARD_VERSION", _guard_version_msg("refactoring_guard", "RULES_VERSION"), "RULES_VERSION"),
        (git_guard_io, "SELF_SKIP_NAMES", SELF_SKIP_MSG, "_SELF_SKIP_NAMES"),
        (lock_policy, "RELEASE_TAG_PATTERN", TAG_MSG, "_RELEASE_TAG_PATTERN"),
    ],
)
def test_deprecated_constant_warns_and_keeps_identity(module: object, name: str, message: str, replacement: str) -> None:
    with pytest.warns(DeprecationWarning, match=re.escape(message)):
        value = getattr(module, name)
    assert value is getattr(module, replacement)
    if name == "SELF_SKIP_NAMES":
        assert value == git_guard_io.GUARD_MODULE_NAMES | git_guard_io.GUARD_TEST_NAMES


def test_unknown_attribute_still_raises_attribute_error() -> None:
    for module in (version, git_guard_io, lock_policy, refactoring_guard):
        with pytest.raises(AttributeError, match="has no attribute 'NOPE'"):
            getattr(module, "NOPE")


def test_new_names_do_not_warn() -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        assert version.VERSION
        assert git_guard_io.RULES_VERSION == "2.3.3"
        assert refactoring_guard.RULES_VERSION == "2.3.3"
        assert lock_policy.RELEASE_TAG_PATTERNS
        importlib.reload(refactoring_guard)


def test_legacy_cli_paths_note_on_stderr_only(capsys: pytest.CaptureFixture[str]) -> None:
    new = _run("-m", "agent_ratchet", "version")
    old = _run("-m", "guard_core", "version")
    assert new.returncode == 0 and old.returncode == 0
    assert new.stderr == ""
    assert old.stderr == GUARD_CORE_MODULE_LINE + "\n"
    assert old.stdout == new.stdout
    assert legacy_main(["version"]) == 0
    captured = capsys.readouterr()
    assert captured.err == GUARD_CORE_SCRIPT_LINE + "\n"
    assert captured.out == new.stdout
    assert main(["version"]) == 0
    assert capsys.readouterr().err == ""
