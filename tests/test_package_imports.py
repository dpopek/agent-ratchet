import importlib
from pathlib import Path

import pytest

MODULES = [
    "ai_slop_scanner",
    "test_baseline_integrity",
    "refactoring_guard",
    "ast_refactoring_delta",
    "ast_safety",
    "ast_topology_guard",
    "ast_control_flow",
    "baseline_diff",
    "cognitive_complexity",
    "git_guard_io",
    "migrate",
    "query_mutation_rules",
    "source_metrics",
]

SRC = Path(__file__).resolve().parents[1] / "src"


@pytest.mark.parametrize("name", MODULES)
def test_every_module_imports(name):
    importlib.import_module(f"agent_ratchet.{name}")


def test_no_scripts_audit_imports():
    offenders = []
    for path in SRC.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        for needle in ("scripts.audit", "sys.path.insert"):
            if needle in text:
                offenders.append((path.name, needle))
    assert offenders == []
