"""Excessively nested guard config or baseline JSON fails closed: exit 2 with a guard_analysis_error, never a traceback."""

from __future__ import annotations

import json
from pathlib import Path
import sys

import pytest

from agent_ratchet import ai_slop_scanner, test_baseline_integrity
from agent_ratchet.json_safety import MAX_JSON_DEPTH

sys.path.insert(0, str(Path(__file__).resolve().parent))
from guard_repo_harness import _commit_files, _git, _init_guard_repo, _json_bytes, _run_baseline_guard, _run_scanner, _write_files

CONFIG = "scripts/audit/audit_guard_config.json"
BASELINE = "tests/baselines/refactoring_slop.json"
DEPTH = 100_000
DEEP_CONFIG = '{"extra_slop_rules": [], "legacy_loc_waivers": [], "deep": ' + "[" * DEPTH + "]" * DEPTH + "}\n"
DEEP_BASELINE = '{"metric": "refactoring_slop", "ceiling": 0, "exemptions": ' + "[" * DEPTH + "]" * DEPTH + "}\n"
MARKER = "nesting-marker"


def _nest(total: int) -> str:
    """Array nesting so that, inside one enclosing object, the document depth is exactly ``total``."""
    inner = total - 1
    return "[" * inner + "]" * inner


def _config_at(total: int) -> str:
    return '{"extra_slop_rules": [], "legacy_loc_waivers": [], "deep": ' + _nest(total) + "}\n"


def _baseline_at(total: int) -> str:
    return '{"metric": "refactoring_slop", "ceiling": 0, "exemptions": ' + _nest(total) + "}\n"


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    r = _init_guard_repo(str(tmp_path))
    _commit_files(r, "chore: initial", {
        "src/app.py": "VALUE = 1\n",
        BASELINE: _json_bytes({"metric": "refactoring_slop", "ceiling": 0, "exemptions": []}),
    }, include_guards=True)
    return r


def _assert_fails_closed(rc: int, stderr: str) -> None:
    assert rc == 2, stderr
    assert "[guard_analysis_error]" in stderr
    assert "Traceback" not in stderr


def _inject_recursion_error(monkeypatch: pytest.MonkeyPatch) -> None:
    real_loads = json.loads

    def loads(s, *args, **kwargs):
        if MARKER in (s if isinstance(s, str) else s.decode("utf-8", "replace")):
            raise RecursionError("maximum recursion depth exceeded")
        return real_loads(s, *args, **kwargs)

    monkeypatch.setattr(json, "loads", loads)


def test_deeply_nested_staged_guard_config_fails_closed(repo: Path) -> None:
    _write_files(repo, {CONFIG: DEEP_CONFIG})
    _git(repo, "add", CONFIG)
    r = _run_scanner(repo, "--staged-only")
    _assert_fails_closed(r.returncode, r.stderr)


@pytest.mark.parametrize("args", [(), ("--staged-only",)], ids=["worktree", "staged"])
def test_deeply_nested_baseline_fails_closed(repo: Path, args: tuple[str, ...]) -> None:
    _write_files(repo, {BASELINE: DEEP_BASELINE})
    _git(repo, "add", BASELINE)
    r = _run_baseline_guard(repo, *args)
    _assert_fails_closed(r.returncode, r.stderr)


def test_injected_recursion_error_in_guard_config_fails_closed(repo: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    _write_files(repo, {CONFIG: json.dumps({"extra_slop_rules": [], "legacy_loc_waivers": [], "note": MARKER}) + "\n"})
    _git(repo, "add", CONFIG)
    monkeypatch.chdir(repo)
    _inject_recursion_error(monkeypatch)
    rc = ai_slop_scanner.main(["--staged-only"])
    _assert_fails_closed(rc, capsys.readouterr().err)


@pytest.mark.parametrize("args", [[], ["--staged-only"]], ids=["worktree", "staged"])
def test_injected_recursion_error_in_baseline_fails_closed(
    repo: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], args: list[str],
) -> None:
    _write_files(repo, {BASELINE: json.dumps({"metric": "refactoring_slop", "ceiling": 0, "exemptions": [], "note": MARKER}) + "\n"})
    _git(repo, "add", BASELINE)
    monkeypatch.chdir(repo)
    _inject_recursion_error(monkeypatch)
    rc = test_baseline_integrity.main(args)
    _assert_fails_closed(rc, capsys.readouterr().err)


def _assert_no_traceback(rc: int, stderr: str) -> None:
    assert rc in (0, 2), stderr
    assert "Traceback" not in stderr


def test_guard_config_at_depth_limit_has_no_traceback(repo: Path) -> None:
    _write_files(repo, {CONFIG: _config_at(MAX_JSON_DEPTH)})
    _git(repo, "add", CONFIG)
    r = _run_scanner(repo, "--staged-only")
    _assert_no_traceback(r.returncode, r.stderr)


def test_guard_config_over_depth_limit_fails_closed(repo: Path) -> None:
    _write_files(repo, {CONFIG: _config_at(MAX_JSON_DEPTH + 1)})
    _git(repo, "add", CONFIG)
    r = _run_scanner(repo, "--staged-only")
    _assert_fails_closed(r.returncode, r.stderr)


@pytest.mark.parametrize("args", [(), ("--staged-only",)], ids=["worktree", "staged"])
def test_baseline_at_depth_limit_has_no_traceback(repo: Path, args: tuple[str, ...]) -> None:
    # Committed first: a new exemption would be rejected (exit 1) on its own merits, so test parse/diff of an unchanged one.
    _commit_files(repo, "chore: nested baseline", {BASELINE: _baseline_at(MAX_JSON_DEPTH)})
    r = _run_baseline_guard(repo, *args)
    _assert_no_traceback(r.returncode, r.stderr)


@pytest.mark.parametrize("args", [(), ("--staged-only",)], ids=["worktree", "staged"])
def test_baseline_over_depth_limit_fails_closed(repo: Path, args: tuple[str, ...]) -> None:
    _write_files(repo, {BASELINE: _baseline_at(MAX_JSON_DEPTH + 1)})
    _git(repo, "add", BASELINE)
    r = _run_baseline_guard(repo, *args)
    _assert_fails_closed(r.returncode, r.stderr)
