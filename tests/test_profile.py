"""Analysis profile keys, strict top-level config keys, and the fail-closed capability check."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import re
import sys

import pytest

from agent_ratchet import cli
from agent_ratchet.git_guard_io import ALLOWED_CONFIG_KEYS, GuardAnalysisError, parse_guard_config_bytes, verify_audit_guard_config_monotonicity
from agent_ratchet.profile import REQUIRED_MODULES, require_profile_capabilities

sys.path.insert(0, str(Path(__file__).resolve().parent))
from guard_repo_harness import _commit_files, _git, _init_guard_repo, _json_bytes

CONFIG = "scripts/audit/audit_guard_config.json"
PHP_MESSAGE = "profile 'php' requires agent-ratchet[php] (set EXTRAS=php in guard.lock)"
MAGENTO_MESSAGE = "profile 'magento' requires agent-ratchet[magento] (set EXTRAS=magento in guard.lock)"


@pytest.mark.parametrize(
    "raw",
    [
        b'{"language": ["php"]}',
        b'{"frameworks": ["magento"], "bogus": 1}',
        b'{"frameworks": ["magento"]}',
        b'{"languages": [], "frameworks": ["magento"]}',
        b'{"languages": ["python"]}',
        b'{"languages": ["php", "php"]}',
        b'{"languages": "php"}',
        b'{"self_skip": {"fixture_path": []}}',
    ],
)
def test_profile_and_key_errors(raw: bytes) -> None:
    with pytest.raises(GuardAnalysisError):
        parse_guard_config_bytes(raw, "x")


def test_unknown_keys_listed_sorted() -> None:
    with pytest.raises(GuardAnalysisError, match=re.escape("Unknown key(s) in audit_guard_config.json at x: ['alpha', 'zeta']")):
        parse_guard_config_bytes(b'{"zeta": 1, "alpha": 2}', "x")


def test_allowed_keys_constant() -> None:
    assert ALLOWED_CONFIG_KEYS == {"extra_slop_rules", "legacy_loc_waivers", "import_roots", "self_skip", "languages", "frameworks"}


def test_profile_parses() -> None:
    cfg = parse_guard_config_bytes(b'{"languages": ["php"], "frameworks": ["magento"]}', "x")
    assert (cfg["languages"], cfg["frameworks"]) == (["php"], ["magento"])


def test_profile_defaults_empty() -> None:
    cfg = parse_guard_config_bytes(b"{}", "x")
    assert (cfg["languages"], cfg["frameworks"]) == ([], [])


def test_required_modules() -> None:
    assert REQUIRED_MODULES == {"php": ("tree_sitter", "tree_sitter_php"), "magento": ("tree_sitter", "tree_sitter_php", "defusedxml")}


def _missing(monkeypatch: pytest.MonkeyPatch, *names: str) -> None:
    monkeypatch.setattr(importlib.util, "find_spec", lambda n, *a: None if n in names else object())


def test_missing_php_extra_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _missing(monkeypatch, "tree_sitter_php")
    with pytest.raises(GuardAnalysisError, match=re.escape(PHP_MESSAGE)):
        require_profile_capabilities({"languages": ["php"], "frameworks": []})


def test_missing_defusedxml_fails_magento(monkeypatch: pytest.MonkeyPatch) -> None:
    _missing(monkeypatch, "defusedxml")
    with pytest.raises(GuardAnalysisError, match=re.escape(MAGENTO_MESSAGE)):
        require_profile_capabilities({"languages": ["php"], "frameworks": ["magento"]})


def test_php_message_wins_for_magento_when_php_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    _missing(monkeypatch, "tree_sitter_php", "defusedxml")
    with pytest.raises(GuardAnalysisError, match=re.escape(PHP_MESSAGE)):
        require_profile_capabilities({"languages": ["php"], "frameworks": ["magento"]})


def test_capability_present_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _missing(monkeypatch)
    require_profile_capabilities({"languages": ["php"], "frameworks": ["magento"]})


def test_no_profile_needs_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(importlib.util, "find_spec", lambda *a: None)
    require_profile_capabilities({"languages": [], "frameworks": []})


@pytest.fixture
def php_repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    repo = _init_guard_repo(str(tmp_path))
    _commit_files(repo, "chore: initial", {CONFIG: _json_bytes({"languages": ["php"]}), "src/app.py": "X = 1\n"}, include_guards=True)
    monkeypatch.chdir(repo)
    monkeypatch.setattr(importlib.util, "find_spec", lambda *a: None)
    return repo


def test_scan_exit_2_when_php_extra_missing(php_repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["scan", "--staged-only"]) == 2
    assert PHP_MESSAGE in capsys.readouterr().err


def test_baseline_integrity_exit_2_when_php_extra_missing(php_repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (php_repo / "src" / "app.py").write_text("X = 2\n", encoding="utf-8")
    _git(php_repo, "add", "src/app.py")
    assert cli.main(["baseline-integrity", "--base-ref", "HEAD"]) == 2
    assert PHP_MESSAGE in capsys.readouterr().err


def test_baseline_integrity_commit_range_exit_2_when_php_extra_missing(php_repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    base = _git(php_repo, "rev-parse", "HEAD")
    _commit_files(php_repo, "feat: change", {"src/app.py": "X = 3\n"})
    assert cli.main(["baseline-integrity", "--commit-range", f"{base}..HEAD"]) == 2
    assert PHP_MESSAGE in capsys.readouterr().err


def test_removing_language_is_reported(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _missing(monkeypatch)
    repo = _init_guard_repo(str(tmp_path))
    base = _commit_files(repo, "chore: initial", {CONFIG: _json_bytes({"languages": ["php"], "frameworks": ["magento"]})}, include_guards=True)
    head = _commit_files(repo, "chore: narrow", {CONFIG: _json_bytes({"languages": [], "frameworks": []})}, include_guards=True)
    errors = verify_audit_guard_config_monotonicity(base, head, str(repo))
    assert "languages entry removed: 'php' (narrows the analysis profile)" in errors
    assert "frameworks entry removed: 'magento' (narrows the analysis profile)" in errors


def test_removing_php_but_keeping_magento_is_a_parse_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _missing(monkeypatch)
    repo = _init_guard_repo(str(tmp_path))
    base = _commit_files(repo, "chore: initial", {CONFIG: _json_bytes({"languages": ["php"], "frameworks": ["magento"]})}, include_guards=True)
    head = _commit_files(repo, "chore: narrow", {CONFIG: _json_bytes({"languages": [], "frameworks": ["magento"]})}, include_guards=True)
    with pytest.raises(GuardAnalysisError, match="requires languages 'php'"):
        verify_audit_guard_config_monotonicity(base, head, str(repo))


def test_adding_language_is_allowed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _missing(monkeypatch)
    repo = _init_guard_repo(str(tmp_path))
    base = _commit_files(repo, "chore: initial", {CONFIG: _json_bytes({})}, include_guards=True)
    head = _commit_files(repo, "chore: widen", {CONFIG: _json_bytes({"languages": ["php"]})}, include_guards=True)
    assert verify_audit_guard_config_monotonicity(base, head, str(repo)) == []
