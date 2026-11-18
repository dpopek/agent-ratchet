"""PHP quality-config protection and PHP-as-code in policy isolation (R7)."""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

import pytest

from agent_ratchet.git_guard_io import is_php_code_path, is_protected_governance_path
from agent_ratchet.test_baseline_integrity import _check_single_commit_policy_isolation

sys.path.insert(0, str(Path(__file__).resolve().parent))
from guard_repo_harness import _commit_files, _init_guard_repo  # noqa: E402

R7_NAMES = [
    "phpstan.neon", "phpstan.dist.neon", "phpstan-strict.neon", "phpstan.neon.dist",
    "phpstan-baseline.neon", "phpstan-baseline.php",
    "phpcs.xml", "phpcs.xml.dist", ".phpcs.xml", ".phpcs.xml.dist",
    "phpunit.xml", "phpunit.xml.dist", "psalm.xml", "psalm.xml.dist", "psalm-baseline.xml",
    ".php-cs-fixer.php", ".php-cs-fixer.dist.php", "phpmd.xml", "rector.php", "captainhook.json",
]


@pytest.mark.parametrize("prefix", ["", "app/code/V/M/"])
@pytest.mark.parametrize("name", R7_NAMES)
def test_quality_config_names_protected(name: str, prefix: str) -> None:
    assert is_protected_governance_path(prefix + name)


@pytest.mark.parametrize("path", ["phpstan.md", "myphpunit.xml", "rector.py", "app/phpstan.txt", "src/phpunit.xml.bak"])
def test_lookalikes_not_protected(path: str) -> None:
    assert not is_protected_governance_path(path)


@pytest.mark.parametrize("path,expected", [
    ("app/code/V/M/X.php", True), ("dev/tests/unit/XTest.php", True), ("view/a.phtml", True),
    ("vendor/a/X.php", False), ("app/vendor/a/X.php", False), ("generated/code/X.php", False),
    ("a.py", False), ("notes.php.txt", False),
])
def test_is_php_code_path(path: str, expected: bool) -> None:
    assert is_php_code_path(path) is expected


def _isolation(files: dict[str, str]) -> tuple[bool, str]:
    with tempfile.TemporaryDirectory() as tmp:
        repo = _init_guard_repo(tmp)
        base = _commit_files(repo, "base", {"README.md": "x\n"})
        head = _commit_files(repo, "change", files)
        return _check_single_commit_policy_isolation(base, head, cwd=str(repo))


def test_commit_mixing_phpstan_and_php_rejected() -> None:
    ok, msg = _isolation({"phpstan.neon": "parameters:\n  level: 5\n", "app/code/V/M/X.php": "<?php\n"})
    assert not ok
    assert msg.startswith("Policy isolation violation")


def test_phpstan_alone_allowed() -> None:
    ok, _ = _isolation({"phpstan.neon": "parameters:\n  level: 5\n"})
    assert ok


def test_vendor_php_not_code() -> None:
    ok, _ = _isolation({"phpstan.neon": "parameters:\n  level: 5\n", "vendor/a/X.php": "<?php\n"})
    assert ok


def test_rector_php_alone_is_governance_not_code() -> None:
    ok, _ = _isolation({"rector.php": "<?php\n"})
    assert ok
