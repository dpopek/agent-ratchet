"""php_paths / php_suppression_exceptions: config validation, scope predicate, and monotonicity."""

from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile

import pytest

from agent_ratchet.git_guard_io import GuardAnalysisError, default_guard_config, parse_guard_config_bytes
from agent_ratchet.php.scope import is_php_in_scope, php_profile_active

sys.path.insert(0, str(Path(__file__).resolve().parent))
from guard_repo_harness import _commit_files, _init_guard_repo, _json_bytes, _run_scanner

CONFIG = "scripts/audit/audit_guard_config.json"
GOOD_EXCEPTION = {"path": "app/code/A/B/X.php", "symbol": "A\\B\\X::run", "tool": "phpstan", "codes": ["z", "a"], "reason": "legacy"}


def _parse(**fields: object) -> dict:
    return parse_guard_config_bytes(json.dumps(fields).encode(), "x")


def test_default_php_paths_cover_app_code() -> None:
    cfg = default_guard_config()
    assert cfg["php_paths"] == ["app/code/", "app/design/", "packages/", "src/"]
    assert cfg["php_suppression_exceptions"] == []
    assert _parse()["php_paths"] == cfg["php_paths"]
    paths = cfg["php_paths"]
    assert is_php_in_scope("app/code/A/B/Model/X.php", paths)
    assert is_php_in_scope("app/design/frontend/A/B/templates/x.phtml", paths)
    for out in ("dev/tests/X.php", "app/code/A/vendor/X.php", "app/code/A/generated/X.php", "app/code/A/x.js"):
        assert not is_php_in_scope(out, paths), out


@pytest.mark.parametrize("value", ["app/code", "../x/", "a/*/", "a\\b/", "a//b/", "./a/", ["a/", "a/"], "app/code/", None, [1]])
def test_invalid_php_paths_exit_2(value: object) -> None:
    with pytest.raises(GuardAnalysisError):
        _parse(php_paths=value)


def test_custom_php_paths_replace_defaults() -> None:
    assert _parse(php_paths=["lib/"])["php_paths"] == ["lib/"]


def test_php_paths_removal_is_monotonicity_error() -> None:
    from agent_ratchet.git_guard_io import verify_audit_guard_config_monotonicity as verify

    with tempfile.TemporaryDirectory() as tmp:
        repo = _init_guard_repo(tmp)
        base = _commit_files(repo, "chore: base", {CONFIG: _json_bytes({"php_paths": ["app/code/", "src/"]})}, include_guards=True)
        narrowed = _commit_files(repo, "chore: narrow", {CONFIG: _json_bytes({"php_paths": ["app/code/"]})}, include_guards=True)
        widened = _commit_files(repo, "chore: widen", {CONFIG: _json_bytes({"php_paths": ["app/code/", "src/", "lib/"]})}, include_guards=True)
        assert verify(base, narrowed, repo) == ["php_paths entry removed: 'src/' (narrows PHP analysis scope)"]
        assert verify(base, widened, repo) == []
        assert "php_paths" not in (_run_scanner(repo, "--diff-base", base, "--head-ref", widened).stderr)


def test_exception_entry_validation() -> None:
    parsed = _parse(php_suppression_exceptions=[GOOD_EXCEPTION])["php_suppression_exceptions"]
    assert parsed == [{**GOOD_EXCEPTION, "codes": ["a", "z"]}]
    bad = [
        {**GOOD_EXCEPTION, "reason": ""},
        {**GOOD_EXCEPTION, "reason": "  "},
        {k: v for k, v in GOOD_EXCEPTION.items() if k != "symbol"},
        {**GOOD_EXCEPTION, "extra": 1},
        {**GOOD_EXCEPTION, "codes": "a"},
        {**GOOD_EXCEPTION, "codes": [1]},
        {**GOOD_EXCEPTION, "tool": ""},
        {**GOOD_EXCEPTION, "symbol": ""},
        {**GOOD_EXCEPTION, "path": "../x.php"},
        "not-a-dict",
    ]
    for entry in bad:
        with pytest.raises(GuardAnalysisError):
            _parse(php_suppression_exceptions=[entry])
    with pytest.raises(GuardAnalysisError):
        _parse(php_suppression_exceptions={})


def test_duplicate_exception_identity_exit_2() -> None:
    twin = {**GOOD_EXCEPTION, "codes": ["a", "z"], "reason": "other reason"}
    with pytest.raises(GuardAnalysisError, match="Duplicate"):
        _parse(php_suppression_exceptions=[GOOD_EXCEPTION, twin])
    other = {**GOOD_EXCEPTION, "symbol": "A\\B\\X::other"}
    assert len(_parse(php_suppression_exceptions=[GOOD_EXCEPTION, other])["php_suppression_exceptions"]) == 2


def test_php_profile_active() -> None:
    assert php_profile_active({"languages": ["php"], "frameworks": []})
    assert php_profile_active({"languages": [], "frameworks": ["magento"]})
    assert not php_profile_active({"languages": [], "frameworks": []})
    assert not php_profile_active({})


def test_pair_entries_marks_only_two_sided_renames_and_copies() -> None:
    from agent_ratchet.php.scan import pair_entries

    paths = ["app/code/"]
    entries = [
        ("R100", "app/code/A/B/X.php", "app/code/A/C/X.php"),
        ("C090", "lib/X.php", "app/code/A/B/Y.php"),
        ("C090", "app/code/A/B/X.php", "app/code/A/B/Z.php"),
        ("A", "app/code/A/B/N.php", "app/code/A/B/N.php"),
        ("D", "app/code/A/B/O.php", "app/code/A/B/O.php"),
        ("M", "app/code/A/B/M.php", "app/code/A/B/M.php"),
    ]
    assert pair_entries(entries, paths) == [
        ("app/code/A/B/X.php", "app/code/A/C/X.php", True),
        (None, "app/code/A/B/Y.php", False),
        ("app/code/A/B/X.php", "app/code/A/B/Z.php", True),
        (None, "app/code/A/B/N.php", False),
        ("app/code/A/B/O.php", None, False),
        ("app/code/A/B/M.php", "app/code/A/B/M.php", False),
    ]
