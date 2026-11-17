"""is_self_skipped decision table and a guard against new basename-only SELF_SKIP_NAMES decisions."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from agent_ratchet import git_guard_io
from agent_ratchet.git_guard_io import GUARD_MODULE_NAMES, GUARD_TEST_NAMES, is_self_skipped

PACKAGE_DIR = Path(__file__).resolve().parent.parent / "src" / "agent_ratchet"


@pytest.mark.parametrize("path", [
    "scripts/audit/source_metrics.py",
    "scripts/audit/sub/source_metrics.py",
    "tests/ci/test_guard_conformance.py",
    "tests/meta_guards/test_suite_quality_ratchet.py",
    "tests/ci/guard_repo_harness.py",
    "tests/audit/ai_slop_scanner.test.ts",
])
def test_skipped(path: str) -> None:
    assert is_self_skipped(path) is True


@pytest.mark.parametrize("path", [
    "src/source_metrics.py",
    "backend/baseline_diff.py",
    "packages/x/git_guard_io.py",
    "scripts/audit/custom.py",
    "src/ai_slop_scanner.test.ts",
    "src/test_guard_conformance.py",
    "tests/ci/source_metrics.py",
    "/abs/scripts/audit/source_metrics.py",
    "./scripts/audit/source_metrics.py",
])
def test_scanned(path: str) -> None:
    assert is_self_skipped(path) is False


def test_deprecated_union_is_exactly_both_sets() -> None:
    with pytest.warns(DeprecationWarning, match="SELF_SKIP_NAMES is deprecated"):
        deprecated = git_guard_io.SELF_SKIP_NAMES
    assert deprecated == set(GUARD_MODULE_NAMES) | set(GUARD_TEST_NAMES)
    assert not GUARD_MODULE_NAMES & GUARD_TEST_NAMES


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
