"""Test Tamper Guard: manifest-verified 2.x guard files may be deleted only by the commit that adopts guard.lock."""

from __future__ import annotations

from pathlib import Path
import sys

import pytest

from guard_core import ai_slop_scanner
from guard_core.ai_slop_scanner import _evaluate_commit_range, _evaluate_transition, check_staged_test_tampering

sys.path.insert(0, str(Path(__file__).resolve().parent))
from guard_repo_harness import _commit_files, _git, _init_guard_repo, _json_bytes, _sha256_bytes

MANIFEST = "scripts/audit/guard_manifest.json"
LISTED = "tests/ci/test_guard_conformance.py"
UNLISTED = "tests/test_app.py"
LOCK = "guard.lock"
LOCK_BODY = "ab" * 20 + "\n"
TAMPER = {"test_file_deleted", "test_assertion_reduction"}


def _test_src(name: str) -> str:
    return f"def test_{name}():\n    assert len('{name}') > 0\n    assert '{name}'.isascii()\n"


def _manifest(files: object) -> bytes:
    return _json_bytes({"guard_version": "2.3.3", "files": files, "baseline_migrations": []})


def _base_repo(tmp_path: Path, manifest: bytes | None = None, base_lock: bool = False) -> Path:
    repo = _init_guard_repo(str(tmp_path))
    listed_src = _test_src("conformance")
    mapping: dict[str, str | bytes] = {
        LISTED: listed_src,
        UNLISTED: _test_src("app"),
        MANIFEST: manifest if manifest is not None else _manifest({LISTED: _sha256_bytes(listed_src.encode())}),
    }
    if base_lock:
        mapping[LOCK] = LOCK_BODY
    _commit_files(repo, "base", mapping, include_guards=True)
    return repo


def _stage_adoption(repo: Path, *deleted: str, lock: str | None = LOCK_BODY, drop_manifest: bool = True) -> None:
    _git(repo, "rm", "-q", *deleted, *([MANIFEST] if drop_manifest else []))
    if lock is not None:
        (repo / LOCK).write_text(lock, encoding="utf-8")
        _git(repo, "add", LOCK)


def _tamper_paths(violations: list[ai_slop_scanner.SlopViolation]) -> set[str]:
    return {v.file for v in violations if v.category in TAMPER}


@pytest.fixture
def no_remote(monkeypatch: pytest.MonkeyPatch) -> None:
    """The lock transition itself is covered by test_lock_policy; here only the tamper accounting is under test."""
    monkeypatch.setattr(ai_slop_scanner, "verify_lock_transition", lambda *a, **k: [])


def test_staged_adoption_exempts_manifest_verified_test(tmp_path: Path, no_remote: None) -> None:
    repo = _base_repo(tmp_path)
    _stage_adoption(repo, LISTED)
    assert _tamper_paths(_evaluate_transition("HEAD", None, cwd=str(repo))) == set()


def test_commit_range_adoption_exempts_per_commit_and_aggregate(tmp_path: Path, no_remote: None) -> None:
    repo = _base_repo(tmp_path)
    base = _git(repo, "rev-parse", "HEAD")
    _stage_adoption(repo, LISTED)
    _git(repo, "commit", "-q", "-m", "adopt guard.lock")
    head = _commit_files(repo, "unrelated", {"README.md": "after adoption\n"})
    assert _tamper_paths(_evaluate_commit_range(f"{base}..{head}", cwd=str(repo))) == set()


def test_commit_range_tampered_listed_test_still_flagged(tmp_path: Path, no_remote: None) -> None:
    repo = _base_repo(tmp_path, manifest=_manifest({LISTED: _sha256_bytes(b"other content\n")}))
    base = _git(repo, "rev-parse", "HEAD")
    _stage_adoption(repo, LISTED)
    _git(repo, "commit", "-q", "-m", "adopt guard.lock")
    head = _git(repo, "rev-parse", "HEAD")
    assert _tamper_paths(_evaluate_commit_range(f"{base}..{head}", cwd=str(repo))) == {LISTED}


def test_tampered_listed_test_flagged(tmp_path: Path) -> None:
    repo = _base_repo(tmp_path, manifest=_manifest({LISTED: _sha256_bytes(b"other content\n")}))
    _stage_adoption(repo, LISTED)
    assert _tamper_paths(check_staged_test_tampering(cwd=str(repo))) == {LISTED}


def test_unlisted_test_flagged_while_listed_exempt(tmp_path: Path) -> None:
    repo = _base_repo(tmp_path)
    _stage_adoption(repo, LISTED, UNLISTED)
    assert _tamper_paths(check_staged_test_tampering(cwd=str(repo))) == {UNLISTED}


@pytest.mark.parametrize("lock", [None, "not-a-sha\n"], ids=["no_lock", "malformed_lock"])
def test_no_valid_lock_adopted_flagged(tmp_path: Path, lock: str | None) -> None:
    repo = _base_repo(tmp_path)
    _stage_adoption(repo, LISTED, lock=lock)
    assert _tamper_paths(check_staged_test_tampering(cwd=str(repo))) == {LISTED}


def test_lock_already_in_base_flagged(tmp_path: Path) -> None:
    repo = _base_repo(tmp_path, base_lock=True)
    _stage_adoption(repo, LISTED, lock="cd" * 20 + "\n")
    assert _tamper_paths(check_staged_test_tampering(cwd=str(repo))) == {LISTED}


@pytest.mark.parametrize("manifest", [b"{not json\n", _manifest([LISTED]), _json_bytes([LISTED])], ids=["invalid_json", "files_not_object", "not_object"])
def test_malformed_manifest_flagged(tmp_path: Path, manifest: bytes) -> None:
    repo = _base_repo(tmp_path, manifest=manifest)
    _stage_adoption(repo, LISTED)
    assert _tamper_paths(check_staged_test_tampering(cwd=str(repo))) == {LISTED}


def test_manifest_kept_flagged(tmp_path: Path) -> None:
    repo = _base_repo(tmp_path)
    _stage_adoption(repo, LISTED, drop_manifest=False)
    assert _tamper_paths(check_staged_test_tampering(cwd=str(repo))) == {LISTED}
