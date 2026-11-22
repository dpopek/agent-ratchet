"""The fleet's stdlib-only copy of the lock grammar table must equal the core's shared table."""

from __future__ import annotations

import importlib.util
from pathlib import Path

from lock_grammar_cases import LOCK_GRAMMAR_CASES

FLEET_TEST = Path(__file__).resolve().parents[1] / "fleet" / "tests" / "test_lockfile.py"


def _load_fleet_cases():
    spec = importlib.util.spec_from_file_location("fleet_test_lockfile_copy", FLEET_TEST)
    module = importlib.util.module_from_spec(spec)
    import sys

    sys.path.insert(0, str(FLEET_TEST.parents[2] / "fleet" / "src"))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
    return module.CASES


def _fields(spec):
    return None if spec is None else (spec.sha, spec.extras)


def test_fleet_copy_equals_core_table():
    fleet = _load_fleet_cases()
    assert len(fleet) == len(LOCK_GRAMMAR_CASES)
    assert [raw for raw, _ in fleet] == [raw for raw, _ in LOCK_GRAMMAR_CASES]
    assert [_fields(e) for _, e in fleet] == [_fields(e) for _, e in LOCK_GRAMMAR_CASES]
