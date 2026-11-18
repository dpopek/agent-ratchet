"""is_self_skipped decision table and a guard against new basename-only SELF_SKIP_NAMES decisions."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from agent_ratchet import git_guard_io
from agent_ratchet.git_guard_io import NO_FIXTURES, is_self_skipped

PACKAGE_DIR = Path(__file__).resolve().parent.parent / "src" / "agent_ratchet"


LISTED = "tests/ci/test_ai_slop_scanner.py"


@pytest.mark.parametrize(("path", "fixtures"), [
    ("scripts/audit/source_metrics.py", NO_FIXTURES),
    ("scripts/audit/sub/source_metrics.py", NO_FIXTURES),
    (LISTED, frozenset({LISTED})),
])
def test_skipped(path: str, fixtures: frozenset[str]) -> None:
    assert is_self_skipped(path, fixture_paths=fixtures) is True


@pytest.mark.parametrize(("path", "fixtures"), [
    ("tests/ci/test_guard_conformance.py", NO_FIXTURES),
    (LISTED, frozenset({"tests/other/test_ai_slop_scanner.py"})),
    ("tests/meta_guards/test_suite_quality_ratchet.py", NO_FIXTURES),
    ("tests/ci/guard_repo_harness.py", NO_FIXTURES),
    ("tests/audit/ai_slop_scanner.test.ts", NO_FIXTURES),
    ("src/source_metrics.py", NO_FIXTURES),
    ("backend/baseline_diff.py", NO_FIXTURES),
    ("packages/x/git_guard_io.py", NO_FIXTURES),
    ("scripts/audit/custom.py", NO_FIXTURES),
    ("src/ai_slop_scanner.test.ts", NO_FIXTURES),
    ("src/test_guard_conformance.py", NO_FIXTURES),
    ("tests/ci/source_metrics.py", NO_FIXTURES),
    ("/abs/scripts/audit/source_metrics.py", NO_FIXTURES),
    ("./scripts/audit/source_metrics.py", NO_FIXTURES),
])
def test_scanned(path: str, fixtures: frozenset[str]) -> None:
    assert is_self_skipped(path, fixture_paths=fixtures) is False


def test_guard_test_names_is_gone() -> None:
    assert not hasattr(git_guard_io, "GUARD_TEST_NAMES")


def _calls_without_fixture_keyword(tree: ast.AST) -> list[int]:
    return [
        node.lineno for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and (getattr(node.func, "id", None) == "is_self_skipped" or getattr(node.func, "attr", None) == "is_self_skipped")
        and not any(kw.arg == "fixture_paths" for kw in node.keywords)
    ]


def test_every_is_self_skipped_call_passes_fixture_paths_by_keyword() -> None:
    offenders = {
        path.name: lines
        for path in sorted(PACKAGE_DIR.rglob("*.py"))
        if (lines := _calls_without_fixture_keyword(ast.parse(path.read_text(encoding="utf-8"), str(path))))
    }
    assert offenders == {}, f"is_self_skipped() needs fixture_paths= by keyword: {offenders}"


def test_keyword_guard_catches_positional_call() -> None:
    assert _calls_without_fixture_keyword(ast.parse("is_self_skipped(p)\nm.is_self_skipped(p, fixture_paths=f)\n")) == [1]


def _self_skip_references(tree: ast.AST) -> list[tuple[int, str]]:
    allowed_lines: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(isinstance(t, ast.Name) and t.id in ("SELF_SKIP_NAMES", "__all__") for t in targets):
                allowed_lines.update(range(node.lineno, (node.end_lineno or node.lineno) + 1))
    hits: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name == "SELF_SKIP_NAMES" and alias.asname not in (None, "SELF_SKIP_NAMES"):
                    hits.append((node.lineno, f"aliased import as {alias.asname}"))
        elif isinstance(node, ast.Name) and node.id == "SELF_SKIP_NAMES" and node.lineno not in allowed_lines:
            hits.append((node.lineno, "name reference"))
        elif isinstance(node, ast.Attribute) and node.attr == "SELF_SKIP_NAMES":
            hits.append((node.lineno, "attribute reference"))
    return hits


def test_no_module_decides_skips_on_basename_set() -> None:
    offenders = {
        path.name: hits
        for path in sorted(PACKAGE_DIR.rglob("*.py"))
        if (hits := _self_skip_references(ast.parse(path.read_text(encoding="utf-8"), str(path))))
    }
    assert offenders == {}, f"use is_self_skipped() instead of SELF_SKIP_NAMES: {offenders}"


def test_completeness_guard_catches_aliased_import_and_direct_use() -> None:
    src = "from agent_ratchet.git_guard_io import SELF_SKIP_NAMES as SKIP\nimport m\nok = 'x' in SELF_SKIP_NAMES or m.SELF_SKIP_NAMES\n"
    kinds = sorted(kind for _, kind in _self_skip_references(ast.parse(src)))
    assert kinds == ["aliased import as SKIP", "attribute reference", "name reference"]
