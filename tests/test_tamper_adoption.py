"""Test Tamper Guard: manifest-verified 2.x guard files may be deleted only by the commit that adopts guard.lock."""

from __future__ import annotations

from pathlib import Path
import sys

import pytest

from agent_ratchet import ai_slop_scanner, lock_policy, transition_scan
from agent_ratchet.ai_slop_scanner import _evaluate_commit_range, _evaluate_transition, check_staged_test_tampering
from agent_ratchet.lock_policy import adopted_guard_files

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
    monkeypatch.setattr(transition_scan, "verify_lock_transition", lambda *a, **k: [])


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


def test_diff_base_adoption_exempts_and_tampered_still_flagged(tmp_path: Path, no_remote: None, monkeypatch: pytest.MonkeyPatch) -> None:
    for name, manifest, expected_rc in (("ok", None, 0), ("tampered", _manifest({LISTED: _sha256_bytes(b"other content\n")}), 1)):
        (tmp_path / name).mkdir()
        repo = _base_repo(tmp_path / name, manifest=manifest)
        base = _git(repo, "rev-parse", "HEAD")
        _stage_adoption(repo, LISTED)
        _git(repo, "commit", "-q", "-m", "adopt guard.lock")
        head = _git(repo, "rev-parse", "HEAD")
        assert _tamper_paths(_evaluate_transition(base, head, cwd=str(repo))) == (set() if expected_rc == 0 else {LISTED})
        monkeypatch.chdir(repo)
        assert ai_slop_scanner.main(["--diff-base", base, "--head-ref", head]) == expected_rc


@pytest.mark.parametrize("kind", ["symlink", "executable"])
def test_non_regular_target_lock_flagged(tmp_path: Path, no_remote: None, kind: str) -> None:
    repo = _base_repo(tmp_path)
    _stage_adoption(repo, LISTED, lock=None)
    if kind == "symlink":
        (repo / "real.lock").write_text(LOCK_BODY, encoding="utf-8")
        (repo / LOCK).symlink_to("real.lock")
        _git(repo, "add", LOCK, "real.lock")
    else:
        (repo / LOCK).write_text(LOCK_BODY, encoding="utf-8")
        _git(repo, "add", LOCK)
        _git(repo, "update-index", "--chmod=+x", LOCK)
    assert adopted_guard_files("HEAD", "", [LISTED], cwd=str(repo)) == frozenset()
    assert _tamper_paths(_evaluate_transition("HEAD", None, cwd=str(repo))) == {LISTED}


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


def test_deeply_nested_manifest_yields_no_exemption(tmp_path: Path) -> None:
    """Real 100 000-level nesting: whether the parser raises or returns, no file is exempted."""
    repo = _base_repo(tmp_path, manifest=b"[" * 100000 + b"]" * 100000)
    _stage_adoption(repo, LISTED)
    assert adopted_guard_files("HEAD", "", [LISTED], cwd=str(repo)) == frozenset()


def test_recursion_error_while_parsing_manifest_yields_no_exemption(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A manifest that would exempt LISTED; an injected RecursionError must take the handler branch, not exempt."""
    repo = _base_repo(tmp_path, manifest=_manifest({LISTED: _sha256_bytes(_test_src("conformance").encode())}))
    _stage_adoption(repo, LISTED)
    assert adopted_guard_files("HEAD", "", [LISTED], cwd=str(repo)) == frozenset({LISTED})

    def _deep(_raw: bytes) -> object:
        raise RecursionError("maximum recursion depth exceeded while decoding a JSON array")

    monkeypatch.setattr(lock_policy.json, "loads", _deep)
    assert adopted_guard_files("HEAD", "", [LISTED], cwd=str(repo)) == frozenset()


def test_uppercase_manifest_hex_exempted(tmp_path: Path) -> None:
    repo = _base_repo(tmp_path, manifest=_manifest({LISTED: _sha256_bytes(_test_src("conformance").encode()).upper()}))
    _stage_adoption(repo, LISTED)
    assert adopted_guard_files("HEAD", "", [LISTED], cwd=str(repo)) == frozenset({LISTED})


@pytest.mark.parametrize("entry", [None, 1, [LISTED]], ids=["null", "int", "list"])
def test_non_str_manifest_entry_not_exempted(tmp_path: Path, entry: object) -> None:
    repo = _base_repo(tmp_path, manifest=_manifest({LISTED: entry}))
    _stage_adoption(repo, LISTED)
    assert adopted_guard_files("HEAD", "", [LISTED], cwd=str(repo)) == frozenset()


def test_manifest_kept_flagged(tmp_path: Path) -> None:
    repo = _base_repo(tmp_path)
    _stage_adoption(repo, LISTED, drop_manifest=False)
    assert _tamper_paths(check_staged_test_tampering(cwd=str(repo))) == {LISTED}
