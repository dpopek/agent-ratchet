"""R10: external config file for local-only operation (no config committed to the scanned repository)."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
from collections.abc import Iterator

import pytest

from agent_ratchet import external_config
from agent_ratchet.git_guard_io import GuardAnalysisError, default_guard_config, load_guard_config_for_ref

sys.path.insert(0, str(Path(__file__).resolve().parent))
from guard_repo_harness import _commit_files, _git, _init_guard_repo, _run_baseline_guard, _run_scanner
from php_support import require_php

PHP_FILE = "app/code/V/M/X.php"
PHP_BASE = "<?php\nclass X {\n    public function f(): int\n    {\n        return 1;\n    }\n}\n"
PHP_HEAD = "<?php\nclass X {\n    public function f(): int\n    {\n        // phpcs:ignore Generic.Foo\n        return 1;\n    }\n}\n"
PHP_CONFIG = {"languages": ["php"]}  # R10 row 14; `frameworks: magento` would also need the defusedxml extra


@pytest.fixture(autouse=True)
def _reset_override() -> Iterator[None]:
    external_config.set_override(None)
    yield
    external_config.set_override(None)


def _write_config(path: Path, payload: object = None, mode: int = 0o444) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({} if payload is None else payload), encoding="utf-8")
    path.chmod(mode)
    return path


def _repo(tmp_path: Path, files_base: dict[str, str], files_head: dict[str, str]) -> tuple[Path, str, str]:
    """A repository without scripts/audit/ and guard.lock."""
    (tmp_path / "repo").mkdir()
    repo = _init_guard_repo(str(tmp_path / "repo"))
    (repo / "scripts" / "audit" / "audit_guard_config.json").unlink()
    base = _commit_files(repo, "base", files_base)
    head = _commit_files(repo, "head", files_head)
    return repo, base, head


def _scan(repo: Path, base: str, head: str, *extra: str, env: dict[str, str] | None = None):
    return _run_scanner(repo, "--diff-base", base, "--head-ref", head, *extra, extra_env=env)


def test_external_config_enables_php_rules(tmp_path: Path) -> None:
    require_php()
    repo, base, head = _repo(tmp_path, {PHP_FILE: PHP_BASE}, {PHP_FILE: PHP_HEAD})
    cfg = _write_config(tmp_path / "cfg" / "c.json", PHP_CONFIG)
    proc = _scan(repo, base, head, "--config-file", str(cfg))
    assert proc.returncode == 1, proc.stderr
    assert "php_suppression_added" in proc.stdout + proc.stderr


def test_external_config_inside_repo_rejected(tmp_path: Path) -> None:
    repo, base, head = _repo(tmp_path, {"a.txt": "1\n"}, {"a.txt": "2\n"})
    inside = _write_config(repo / "local.json")
    proc = _scan(repo, base, head, "--config-file", str(inside))
    assert proc.returncode == 2
    assert "outside the repository" in proc.stderr


def test_symlink_outside_pointing_inside_rejected(tmp_path: Path) -> None:
    repo, base, head = _repo(tmp_path, {"a.txt": "1\n"}, {"a.txt": "2\n"})
    inside = _write_config(repo / "local.json")
    link = tmp_path / "ext" / "link.json"
    link.parent.mkdir()
    link.symlink_to(inside)
    proc = _scan(repo, base, head, "--config-file", str(link))
    assert proc.returncode == 2
    assert "outside the repository" in proc.stderr


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode bits")
@pytest.mark.parametrize("mode", [0o664, 0o646])
def test_group_or_world_writable_config_rejected(tmp_path: Path, mode: int) -> None:
    repo, base, head = _repo(tmp_path, {"a.txt": "1\n"}, {"a.txt": "2\n"})
    cfg = _write_config(tmp_path / "cfg" / "c.json", mode=mode)
    proc = _scan(repo, base, head, "--config-file", str(cfg))
    assert proc.returncode == 2
    assert "writable" in proc.stderr


def test_option_wins_over_env(tmp_path: Path) -> None:
    repo, base, head = _repo(tmp_path, {"a.txt": "1\n"}, {"a.txt": "2\n"})
    good = _write_config(tmp_path / "cfg" / "good.json")
    bad = _write_config(tmp_path / "cfg" / "bad.json", {"no_such_key": 1})
    env = {"AGENT_RATCHET_CONFIG": str(bad)}
    assert _scan(repo, base, head, env=env).returncode == 2
    proc = _scan(repo, base, head, "--config-file", str(good), env=env)
    assert proc.returncode == 0, proc.stderr
    assert f"note: using external config {good.resolve()}" in proc.stderr


def test_empty_env_is_unset(tmp_path: Path) -> None:
    repo, base, head = _repo(tmp_path, {"a.txt": "1\n"}, {"a.txt": "2\n"})
    proc = _scan(repo, base, head, env={"AGENT_RATCHET_CONFIG": ""})
    assert proc.returncode == 0, proc.stderr
    assert "external config" not in proc.stderr


def test_env_var_is_used(tmp_path: Path) -> None:
    repo, base, head = _repo(tmp_path, {"a.txt": "1\n"}, {"a.txt": "2\n"})
    good = _write_config(tmp_path / "cfg" / "good.json")
    proc = _scan(repo, base, head, env={"AGENT_RATCHET_CONFIG": str(good)})
    assert proc.returncode == 0, proc.stderr
    assert "external config" in proc.stderr


@pytest.mark.parametrize("kind", ["missing", "not_json", "unknown_key", "bad_profile"])
def test_missing_or_invalid_file_exit_2(tmp_path: Path, kind: str) -> None:
    repo, base, head = _repo(tmp_path, {"a.txt": "1\n"}, {"a.txt": "2\n"})
    cfg = tmp_path / "cfg" / "c.json"
    if kind == "not_json":
        cfg.parent.mkdir()
        cfg.write_text("{nope", encoding="utf-8")
        cfg.chmod(0o444)
    elif kind != "missing":
        _write_config(cfg, {"unknown_key": 1} if kind == "unknown_key" else {"frameworks": ["magento"]})
    proc = _scan(repo, base, head, "--config-file", str(cfg))
    assert proc.returncode == 2
    assert "guard_analysis_error" in proc.stderr


def test_note_line_printed_once(tmp_path: Path) -> None:
    repo, base, head = _repo(tmp_path, {"a.txt": "1\n"}, {"a.txt": "2\n"})
    cfg = _write_config(tmp_path / "cfg" / "c.json")
    proc = _scan(repo, base, head, "--config-file", str(cfg))
    assert proc.returncode == 0, proc.stderr
    assert proc.stderr.splitlines().count(f"note: using external config {cfg.resolve()}") == 1
    assert proc.stderr.count("note: using external config") == 1


def test_baseline_integrity_accepts_config_file(tmp_path: Path) -> None:
    repo, base, _head = _repo(tmp_path, {"a.txt": "1\n"}, {"a.txt": "2\n"})
    cfg = _write_config(tmp_path / "cfg" / "c.json")
    proc = _run_baseline_guard(repo, "--base-ref", base, "--config-file", str(cfg))
    assert proc.returncode == 0, proc.stderr
    assert proc.stderr.count("note: using external config") == 1
    bad = _run_baseline_guard(repo, "--base-ref", base, "--config-file", str(tmp_path / "missing.json"))
    assert bad.returncode == 2


def test_no_lock_no_lock_transition_error(tmp_path: Path) -> None:
    repo, base, head = _repo(tmp_path, {"a.txt": "1\n"}, {"a.txt": "2\n"})
    cfg = _write_config(tmp_path / "cfg" / "c.json")
    proc = _scan(repo, base, head, "--config-file", str(cfg))
    assert proc.returncode == 0, proc.stderr
    assert "guard.lock" not in proc.stdout + proc.stderr


def test_no_override_behaviour_unchanged(tmp_path: Path) -> None:
    (tmp_path / "repo").mkdir()
    repo = _init_guard_repo(str(tmp_path / "repo"))
    _commit_files(repo, "base", {"a.txt": "1\n"}, include_guards=True)
    assert external_config.active_override() is None
    assert load_guard_config_for_ref("HEAD", cwd=str(repo)) == default_guard_config()
    (repo / "scripts" / "audit" / "audit_guard_config.json").write_text(json.dumps({"import_roots": ["zzz"]}), encoding="utf-8")
    _commit_files(repo, "cfg", {"b.txt": "1\n"}, include_guards=True)
    assert load_guard_config_for_ref("HEAD", cwd=str(repo))["import_roots"] == ["zzz"]


def test_override_replaces_config_for_every_ref(tmp_path: Path) -> None:
    (tmp_path / "repo").mkdir()
    repo = _init_guard_repo(str(tmp_path / "repo"))
    _commit_files(repo, "base", {"a.txt": "1\n"}, include_guards=True)
    cfg = _write_config(tmp_path / "cfg" / "c.json", {"import_roots": ["only_me"]})
    external_config.set_override(external_config.load_external_config(cfg))
    for ref in ("HEAD", "", "WORKTREE"):
        assert load_guard_config_for_ref(ref, cwd=str(repo))["import_roots"] == ["only_me"]


def test_case_variant_path_inside_repo_rejected(tmp_path: Path) -> None:
    repo, base, head = _repo(tmp_path, {"a.txt": "1\n"}, {"a.txt": "2\n"})
    if not (tmp_path / "REPO").exists():
        pytest.skip("case-sensitive filesystem")
    inside = _write_config(repo / "cfg.json")
    variant = tmp_path / "REPO" / "cfg.json"
    assert variant.exists() and str(variant) != str(inside)
    proc = _scan(repo, base, head, "--config-file", str(variant))
    assert proc.returncode == 2
    assert "outside the repository" in proc.stderr


def _worktree(tmp_path: Path) -> tuple[Path, Path, str, str]:
    repo, base, head = _repo(tmp_path, {"a.txt": "1\n"}, {"a.txt": "2\n"})
    wt = tmp_path / "wt"
    _git(repo, "worktree", "add", "-q", str(wt), head)
    return repo, wt, base, head


@pytest.mark.parametrize("where", ["main_checkout", "git_dir"])
def test_config_in_main_checkout_of_linked_worktree_rejected(tmp_path: Path, where: str) -> None:
    repo, wt, base, head = _worktree(tmp_path)
    cfg = _write_config((repo if where == "main_checkout" else repo / ".git") / "cfg.json")
    proc = _scan(wt, base, head, "--config-file", str(cfg))
    assert proc.returncode == 2
    assert "outside the repository" in proc.stderr


def test_config_outside_linked_worktree_and_main_checkout_accepted(tmp_path: Path) -> None:
    _repo_dir, wt, base, head = _worktree(tmp_path)
    cfg = _write_config(tmp_path / "cfg" / "c.json")
    proc = _scan(wt, base, head, "--config-file", str(cfg))
    assert proc.returncode == 0, proc.stderr


MANIFEST_PATH = "scripts/audit/guard_manifest.json"
MANIFEST = '{"guard_version": "2.3.3", "files": {}, "baseline_migrations": []}\n'


def test_legacy_manifest_change_ignored_only_with_override(tmp_path: Path) -> None:
    repo, base, head = _repo(tmp_path, {MANIFEST_PATH: MANIFEST}, {MANIFEST_PATH: MANIFEST.replace("2.3.3", "2.3.4")})
    control = _scan(repo, base, head)
    assert control.returncode != 0 and "guard_manifest.json changed" in control.stdout + control.stderr
    cfg = _write_config(tmp_path / "cfg" / "c.json")
    proc = _scan(repo, base, head, "--config-file", str(cfg))
    assert proc.returncode == 0, proc.stderr


def test_shim_change_without_lock_ignored_only_with_override(tmp_path: Path) -> None:
    repo, base, head = _repo(tmp_path, {"scripts/guard": "#!/bin/sh\n# one\n"}, {"scripts/guard": "#!/bin/sh\n# two\n"})
    control = _scan(repo, base, head)
    assert control.returncode != 0 and "scripts/guard" in control.stdout + control.stderr
    cfg = _write_config(tmp_path / "cfg" / "c.json")
    proc = _scan(repo, base, head, "--config-file", str(cfg))
    assert proc.returncode == 0, proc.stderr


def test_staged_only_with_override_and_no_pin(tmp_path: Path) -> None:
    repo, _base, _head = _repo(tmp_path, {MANIFEST_PATH: MANIFEST}, {"a.txt": "1\n"})
    _git(repo, "rm", "-q", MANIFEST_PATH)
    control = _run_scanner(repo, "--staged-only")
    assert control.returncode == 2 and "guard_manifest.json was deleted" in control.stderr
    cfg = _write_config(tmp_path / "cfg" / "c.json")
    proc = _run_scanner(repo, "--staged-only", "--config-file", str(cfg))
    assert proc.returncode == 0, proc.stderr


def test_resolve_precedence_and_unset(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    a, b = _write_config(tmp_path / "a.json"), _write_config(tmp_path / "b.json")
    monkeypatch.setenv("AGENT_RATCHET_CONFIG", str(b))
    assert external_config.resolve_external_config(str(a), repo) == a.resolve()
    assert external_config.resolve_external_config(None, repo) == b.resolve()
    monkeypatch.setenv("AGENT_RATCHET_CONFIG", "")
    assert external_config.resolve_external_config(None, repo) is None
    monkeypatch.delenv("AGENT_RATCHET_CONFIG")
    assert external_config.resolve_external_config(None, repo) is None


def test_load_external_config_fills_defaults(tmp_path: Path) -> None:
    cfg = external_config.load_external_config(_write_config(tmp_path / "c.json", {"languages": ["php"]}))
    assert cfg["languages"] == ["php"]
    assert cfg["php_paths"] == default_guard_config()["php_paths"]
    with pytest.raises(GuardAnalysisError):
        external_config.load_external_config(tmp_path / "absent.json")


# --- I4: a repository that adopted guard.lock ignores AGENT_RATCHET_CONFIG (only --config-file overrides) ----

LOCK = "guard.lock"
LOCK_BODY = "ab" * 20 + "\n"
ENV_IGNORED_NOTE = "note: ignoring AGENT_RATCHET_CONFIG because guard.lock is present; using the in-repo config"


def _lock_repo(tmp_path: Path, lock_base: bool, lock_head: bool) -> tuple[Path, str, str]:
    """In-repo config requests the php profile; guard.lock present at BASE and/or HEAD as asked."""
    (tmp_path / "repo").mkdir()
    repo = _init_guard_repo(str(tmp_path / "repo"))
    (repo / "scripts" / "audit" / "audit_guard_config.json").write_text(json.dumps(PHP_CONFIG), encoding="utf-8")
    base = _commit_files(repo, "base", {PHP_FILE: PHP_BASE, **({LOCK: LOCK_BODY} if lock_base else {})}, include_guards=True)
    if lock_base and not lock_head:
        _git(repo, "rm", "-q", LOCK)
    head = _commit_files(repo, "head", {PHP_FILE: PHP_HEAD, **({LOCK: LOCK_BODY} if lock_head and not lock_base else {})})
    return repo, base, head


@pytest.mark.parametrize(("lock_base", "lock_head"), [(True, True), (True, False), (False, True)])
def test_env_override_ignored_when_lock_at_base_or_target(tmp_path: Path, lock_base: bool, lock_head: bool) -> None:
    require_php()
    repo, base, head = _lock_repo(tmp_path, lock_base, lock_head)
    off = _write_config(tmp_path / "cfg" / "off.json", {"no_such_key": 1})  # would be exit 2 if it were read
    proc = _scan(repo, base, head, env={"AGENT_RATCHET_CONFIG": str(off)})
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert ENV_IGNORED_NOTE in proc.stderr and "note: using external config" not in proc.stderr
    if lock_base and lock_head:
        assert "php_suppression_added" in proc.stdout + proc.stderr


def test_env_override_ignored_on_staged_scan_with_lock(tmp_path: Path) -> None:
    require_php()
    repo, _base, _head = _lock_repo(tmp_path, True, True)
    (repo / PHP_FILE).write_text(PHP_HEAD.replace("Generic.Foo", "Generic.Bar"), encoding="utf-8")
    _git(repo, "add", PHP_FILE)
    off = _write_config(tmp_path / "cfg" / "off.json", {})
    proc = _run_scanner(repo, "--staged-only", extra_env={"AGENT_RATCHET_CONFIG": str(off)})
    assert proc.returncode == 1 and "php_suppression_added" in proc.stdout + proc.stderr, proc.stderr
    assert ENV_IGNORED_NOTE in proc.stderr


def test_config_file_option_still_honoured_with_lock(tmp_path: Path) -> None:
    require_php()
    repo, base, head = _lock_repo(tmp_path, True, True)
    off = _write_config(tmp_path / "cfg" / "off.json", {})
    proc = _scan(repo, base, head, "--config-file", str(off), env={"AGENT_RATCHET_CONFIG": str(off)})
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert f"note: using external config {off.resolve()}" in proc.stderr and ENV_IGNORED_NOTE not in proc.stderr


def test_env_override_ignored_by_baseline_integrity_with_lock(tmp_path: Path) -> None:
    require_php()
    repo, base, _head = _lock_repo(tmp_path, True, True)
    off = _write_config(tmp_path / "cfg" / "off.json", {"no_such_key": 1})
    proc = _run_baseline_guard(repo, "--base-ref", base, extra_env={"AGENT_RATCHET_CONFIG": str(off)})
    assert proc.returncode == 0 and "no_such_key" not in proc.stdout + proc.stderr, proc.stderr
    assert ENV_IGNORED_NOTE in proc.stderr and "note: using external config" not in proc.stderr


def test_env_override_ignored_when_lock_only_inside_commit_range(tmp_path: Path) -> None:
    require_php()
    repo, base, head = _lock_repo(tmp_path, False, True)
    _git(repo, "rm", "-q", LOCK)
    tip = _commit_files(repo, "drop lock", {"a.txt": "1\n"})
    off = _write_config(tmp_path / "cfg" / "off.json", {"no_such_key": 1})
    proc = _run_scanner(repo, "--commit-range", f"{base}..{tip}", extra_env={"AGENT_RATCHET_CONFIG": str(off)})
    assert proc.returncode == 1 and "no_such_key" not in proc.stdout + proc.stderr, proc.stderr
    assert "php_suppression_added" in proc.stderr  # the in-repo PHP config was read, not the external one
    assert ENV_IGNORED_NOTE in proc.stderr and "note: using external config" not in proc.stderr


def test_activation_without_config_clears_a_previous_override(tmp_path: Path, monkeypatch) -> None:
    """Audit D6: an override from an earlier run in the same process must not leak into the next one."""
    monkeypatch.delenv(external_config.ENV_VAR, raising=False)
    cfg = _write_config(tmp_path / "cfg" / "c.json", PHP_CONFIG)
    (tmp_path / "work").mkdir()
    assert external_config.activate_cli(str(cfg), cwd=str(tmp_path / "work")) is None
    assert external_config.override_active()
    assert external_config.activate_cli(None, cwd=str(tmp_path / "work")) is None
    assert not external_config.override_active()
