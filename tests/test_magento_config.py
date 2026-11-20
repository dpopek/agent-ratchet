"""Trusted `magento_di_exceptions` config key: validation, parsing and monotonicity (no optional deps)."""

from __future__ import annotations

from pathlib import Path
import sys

import pytest

from agent_ratchet.git_guard_io import GuardAnalysisError, default_guard_config, parse_guard_config_bytes, verify_audit_guard_config_monotonicity
from agent_ratchet.magento.config import MAGENTO_EXCEPTION_KEYS, validate_magento_exceptions

sys.path.insert(0, str(Path(__file__).resolve().parent))
from guard_repo_harness import _commit_files, _init_guard_repo, _json_bytes

CONFIG = "scripts/audit/audit_guard_config.json"
ENTRY = {"area": "frontend", "target": "\\Vendor\\Module\\Model\\Foo", "plugin": "vendor_foo", "reason": "reviewed"}


def test_keys_constant() -> None:
    assert MAGENTO_EXCEPTION_KEYS == {"area", "target", "plugin", "reason"}


def test_valid_entry_strips_leading_backslash() -> None:
    out = validate_magento_exceptions([ENTRY], "x")
    assert out == [{**ENTRY, "target": "Vendor\\Module\\Model\\Foo"}]


def test_empty_list_ok() -> None:
    assert validate_magento_exceptions([], "x") == []


@pytest.mark.parametrize(
    "value",
    [
        "nope",
        {"a": 1},
        ["str"],
        [{k: v for k, v in ENTRY.items() if k != "plugin"}],
        [{**ENTRY, "extra": "x"}],
        [{**ENTRY, "reason": "   "}],
        [{**ENTRY, "area": ""}],
        [{**ENTRY, "target": 5}],
        [ENTRY, {**ENTRY, "target": "Vendor\\Module\\Model\\Foo", "reason": "other"}],
    ],
)
def test_invalid_raises(value: object) -> None:
    with pytest.raises(GuardAnalysisError, match="magento_di_exceptions"):
        validate_magento_exceptions(value, "x")


def test_parse_and_default_config() -> None:
    assert parse_guard_config_bytes(b'{"magento_di_exceptions": []}', "x")["magento_di_exceptions"] == []
    assert parse_guard_config_bytes(b"{}", "x")["magento_di_exceptions"] == []
    assert default_guard_config()["magento_di_exceptions"] == []


def test_parse_validates_without_profile() -> None:
    with pytest.raises(GuardAnalysisError, match="magento_di_exceptions"):
        parse_guard_config_bytes(b'{"magento_di_exceptions": [{"area": "x"}]}', "x")


def test_add_and_remove_entries_are_not_monotonicity_errors(tmp_path: Path) -> None:
    repo = _init_guard_repo(str(tmp_path))
    empty = _commit_files(repo, "chore: initial", {CONFIG: _json_bytes({})}, include_guards=True)
    with_entry = _commit_files(repo, "chore: add", {CONFIG: _json_bytes({"magento_di_exceptions": [ENTRY]})}, include_guards=True)
    removed = _commit_files(repo, "chore: remove", {CONFIG: _json_bytes({"magento_di_exceptions": []})}, include_guards=True)
    assert verify_audit_guard_config_monotonicity(empty, with_entry, str(repo)) == []
    assert verify_audit_guard_config_monotonicity(with_entry, removed, str(repo)) == []
