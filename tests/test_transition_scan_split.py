from pathlib import Path

import pytest

from agent_ratchet import ai_slop_scanner, transition_scan

MOVED = [
    "_evaluate_transition",
    "_evaluate_commit_range",
    "_new_or_worsened_text_slop",
    "_load_python_snapshot_files",
    "_py_entry_needs_a2",
    "_evaluate_entry_transition",
    "_check_aggregate_range_loc",
]


@pytest.mark.parametrize("name", MOVED)
def test_scanner_reexports_moved_names(name):
    assert getattr(ai_slop_scanner, name) is getattr(transition_scan, name)


def test_scanner_loc_not_grown():
    path = Path(ai_slop_scanner.__file__)
    assert len(path.read_text(encoding="utf-8").splitlines()) <= 680


def test_transition_scan_does_not_import_scanner():
    assert "ai_slop_scanner" not in Path(transition_scan.__file__).read_text(encoding="utf-8")
