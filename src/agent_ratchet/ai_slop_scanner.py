#!/usr/bin/env python3
"""Git-blob-isolated AST, topology (A2), regex, and diff scanner (RULES_VERSION = "2.3.3")."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import sys
from typing import Any, Sequence

from agent_ratchet.git_guard_io import (
    CODE_SCAN_EXTS, GuardAnalysisError as GuardAnalysisError, SlopViolation as SlopViolation,
    check_staged_file_size_buffer as check_staged_file_size_buffer, count_test_assertions as count_test_assertions,
    diff_name_status, is_self_skipped, load_guard_config_for_ref,
    verify_commit_ref,
)
from agent_ratchet.git_batch import git_batch_session
from agent_ratchet.lock_policy import check_staged_lock
from agent_ratchet.refactoring_guard import scan_ast_for_refactoring_slop as scan_ast_for_refactoring_slop
from agent_ratchet.slop_text_scan import scan_diff_for_shortcut_escapes, scan_text_for_slop
from agent_ratchet.transition_scan import (
    _check_aggregate_range_loc as _check_aggregate_range_loc, _check_transition_test_tampering,
    _evaluate_commit_range, _evaluate_entry_transition as _evaluate_entry_transition, _evaluate_transition,
    _load_python_snapshot_files as _load_python_snapshot_files,
    _new_or_worsened_text_slop as _new_or_worsened_text_slop, _py_entry_needs_a2 as _py_entry_needs_a2,
)

__all__ = [
    "GuardAnalysisError", "SlopViolation", "check_staged_file_size_buffer", "check_staged_test_tampering",
    "count_test_assertions", "load_worktree_guard_config", "scan_ast_for_refactoring_slop",
    "scan_diff_for_shortcut_escapes", "scan_text_for_slop",
]


def load_worktree_guard_config(cwd: str | None = None) -> dict[str, Any]:
    return load_guard_config_for_ref("WORKTREE", cwd=cwd)


def check_staged_test_tampering(cwd: str | None = None) -> list[SlopViolation]:
    return _check_transition_test_tampering(diff_name_status(None, None, cwd=cwd), "HEAD", "", cwd=cwd)


def run_fixtures_self_test() -> bool:
    dirty_fixture = (
        "// Certainly! Here is the implementation:\n"
        "const payload = { get event() { throw new Error('boom'); } };\n"
        "expect(true).toBe(true);\n"
        "def test_stub(): pass\n"
    )
    clean_fixture = "const title = res.cardsV2[0].card.header.title;\nexpect(title).toBe('Expected Title');\n"
    assert len(scan_text_for_slop(dirty_fixture, "fixture_dirty.test.js")) >= 4
    assert len(scan_text_for_slop(clean_fixture, "fixture_clean.test.js")) == 0
    diff_dirty = "+++ b/tests/test_x.py\n+@pytest.mark.skip\n+x = 1  # noqa\n+# Wave 5 fix_v2\n"
    diff_clean = "+++ b/tests/test_x.py\n+x = 1  # noqa: E501 -- valid reason here\n"
    assert len(scan_diff_for_shortcut_escapes(diff_dirty)) >= 3
    assert len(scan_diff_for_shortcut_escapes(diff_clean)) == 0
    ast_dirty = "_default_factory = None\ndef bad(a, b, c, d, e, f):\n    from src.x import _priv\n    return getattr(a, 'k', None)\n"
    assert len(scan_ast_for_refactoring_slop(ast_dirty, "src/domain/sample.py")) >= 4
    print("✅ ai_slop_scanner fixtures self-test passed.")
    return True


_SKIP_SCAN_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", ".next", "coverage"}


def _resolve_scan_targets(args: argparse.Namespace) -> list[Path]:
    targets: list[Path] = []
    roots = args.files if args.files else [f for f in ("src", "backend", "web", "mobile", "packages", "test", "tests") if Path(f).exists()]
    for f in roots:
        p = Path(f)
        if p.is_dir():
            for ext in tuple(f"*{e}" for e in CODE_SCAN_EXTS):
                targets.extend(cand for cand in p.rglob(ext) if not any(part in _SKIP_SCAN_DIRS for part in cand.parts))
        elif p.exists():
            targets.append(p)
    return targets


def _scan_root(cwd: str | None) -> Path:
    try:
        top = subprocess.check_output(["git", "rev-parse", "--show-toplevel"], cwd=cwd, text=True, stderr=subprocess.DEVNULL).strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        top = ""
    return Path(top or cwd or os.getcwd()).resolve()


def _is_self_skipped_target(path: Path, root: Path, cwd: str | None, fixture_paths: frozenset[str]) -> bool:
    """Self-skip decision for a CLI target: resolved and made repo-relative POSIX; targets outside the root never skip."""
    resolved = (path if path.is_absolute() else Path(cwd or os.getcwd()) / path).resolve()
    try:
        return is_self_skipped(resolved.relative_to(root).as_posix(), fixture_paths=fixture_paths)
    except ValueError:
        return False


def _scan_worktree_files(targets: list[Path], cwd: str | None = None) -> list[SlopViolation]:
    wt_cfg = load_worktree_guard_config(cwd=cwd)
    extra_rules, fixtures = wt_cfg["extra_slop_rules"], frozenset(wt_cfg["fixture_paths"])
    all_violations: list[SlopViolation] = []
    valid_exts = set(CODE_SCAN_EXTS)
    root = _scan_root(cwd)
    for path in targets:
        if path.suffix not in valid_exts or _is_self_skipped_target(path, root, cwd, fixtures):
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise GuardAnalysisError(f"Failed to read {path}: {exc}") from exc
        rel_str = str(path)
        all_violations.extend(scan_text_for_slop(content, rel_str, extra_rules=extra_rules))
        if path.suffix == ".py":
            all_violations.extend(v for v in scan_ast_for_refactoring_slop(content, rel_str, changed_lines=set(), extra_rules=extra_rules) if v.category == "syntax_error")
    return all_violations


def _report_violations(all_violations: list[SlopViolation]) -> int:
    analysis_errors = [v for v in all_violations if v.category in ("syntax_error", "guard_analysis_error")]
    if analysis_errors:
        print(f"\n❌ Guard Analysis Error ({len(analysis_errors)}):", file=sys.stderr)
        for v in analysis_errors:
            print(f"  {v.file}:{v.line} -> [{v.category}] {v.message}", file=sys.stderr)
        return 2

    print(f"\n❌ AI Slop / Anti-Shortcutting Violations Detected ({len(all_violations)}):", file=sys.stderr)
    for v in all_violations:
        print(f"  {v.file}:{v.line} -> [{v.category}] {v.message}", file=sys.stderr)
        print(f"    Snippet: {v.snippet}", file=sys.stderr)
    return 1


FILE_SCAN_SCOPE_NOTE = (
    "note: file scan runs text rules and syntax checks only; use --staged-only, --diff-base or --commit-range "
    "for AST, topology and test-integrity checks"
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="AI Slop & Anti-Hacking Scanner")
    parser.add_argument("--staged-only", action="store_true", help="Scan git index against HEAD")
    parser.add_argument("--diff-base", default=None, help="Base commit ref for single diff scan")
    parser.add_argument("--head-ref", default="HEAD", help="Target commit ref for --diff-base")
    parser.add_argument("--commit-range", default=None, help="Commit range <base>..<head> for per-commit + aggregate scan")
    parser.add_argument("--test-fixtures", action="store_true", help="Run self-test against fixtures")
    parser.add_argument("files", nargs="*", help="Specific files or folders to scan")
    args = parser.parse_args(argv)
    with git_batch_session():
        return _run_scan(args)


def _emit_shadow_report(violations: Sequence[SlopViolation]) -> None:
    """Opt-in (AGENT_RATCHET_SHADOW=1) stderr-only fact parity check; never affects stdout or the exit code."""
    if os.environ.get("AGENT_RATCHET_SHADOW") != "1":
        return
    try:
        from agent_ratchet.facts.legacy import shadow_report

        print(shadow_report(violations), file=sys.stderr)
    except Exception as exc:
        print(f"agent-ratchet shadow: failed ({type(exc).__name__})", file=sys.stderr)


def _run_scan(args: argparse.Namespace) -> int:
    if args.test_fixtures:
        return 0 if run_fixtures_self_test() else 1
    lock_rc = check_staged_lock() if args.staged_only else None
    if lock_rc is not None:
        return lock_rc

    try:
        if args.commit_range:
            all_violations = _evaluate_commit_range(args.commit_range)
        elif args.diff_base:
            base_sha = verify_commit_ref(args.diff_base)
            head_sha = verify_commit_ref(args.head_ref)
            all_violations = _evaluate_transition(base_sha, head_sha)
        elif args.staged_only:
            all_violations = _evaluate_transition("HEAD", None)
        else:
            print(FILE_SCAN_SCOPE_NOTE, file=sys.stderr)
            targets = _resolve_scan_targets(args)
            all_violations = _scan_worktree_files(targets)
    except GuardAnalysisError as exc:
        print(f"ERROR: [guard_analysis_error] {exc}", file=sys.stderr)
        return 2

    _emit_shadow_report(all_violations)
    if all_violations:
        return _report_violations(all_violations)

    if args.staged_only or args.commit_range or args.diff_base:
        print("✅ Git snapshot clean of AI slop, AST regressions, shortcut escapes, and test tampering.")
    else:
        print("✅ Scanned files — zero slop violations detected.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
