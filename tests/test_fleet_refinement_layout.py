"""The refined scan layout (4.4.1) as the fleet classifier sees this very tree."""

from __future__ import annotations

import ast
from pathlib import Path

from fleet_import import guard_fleet, load_tree_from_worktree

guard_fleet()

from guard_fleet.classify import Level  # noqa: E402 -- guard_fleet() puts fleet/src on sys.path first
from guard_fleet.classify.graph import module_edges  # noqa: E402 -- guard_fleet() puts fleet/src on sys.path first
from guard_fleet.classify.surfaces import compute_surfaces  # noqa: E402 -- guard_fleet() puts fleet/src on sys.path first
from guard_fleet.classify.tree import module_name  # noqa: E402 -- guard_fleet() puts fleet/src on sys.path first

ROOT = Path(__file__).resolve().parents[1]
SCAN_SURFACE = {"agent_ratchet.php.scan": Level.PHP, "agent_ratchet.magento.scan": Level.MAGENTO,
                "agent_ratchet.magento.di": Level.MAGENTO, "agent_ratchet.magento.xml_safe": Level.MAGENTO}


def test_scan_modules_are_surface_on_this_tree():
    m = compute_surfaces(load_tree_from_worktree(ROOT))
    assert m.all_core_reason is None
    assert {k: m.level_of[k] for k in SCAN_SURFACE} == SCAN_SURFACE
    for core in ("transition_scan", "violation_dedupe", "php.scope", "magento.config", "git_guard_io"):
        assert m.level_of[f"agent_ratchet.{core}"] is Level.CORE


def test_transition_scan_g_blocks_are_recognised():
    m = compute_surfaces(load_tree_from_worktree(ROOT))
    sites = {(g.func, g.kind, g.level) for g in m.gates if g.module == "agent_ratchet.transition_scan"}
    assert sites == {("_evaluate_transition", "block", Level.PHP), ("_evaluate_transition", "block", Level.MAGENTO)}


def core_edges_into(targets: dict[str, Level]) -> set[tuple[str, Level]]:
    """(source module, gate level) of every import edge from a core module into `targets`; ungated = CORE."""
    tree = load_tree_from_worktree(ROOT)
    m = compute_surfaces(tree)
    known = frozenset(m.level_of)
    found: set[tuple[str, Level]] = set()
    for path, raw in tree.files.items():
        mod = module_name(path)
        if mod is None or m.level_of.get(mod) is not Level.CORE:
            continue
        for e in module_edges(mod, ast.parse(raw), known):
            if e.dst in targets:
                found.add((e.src, e.level))
    return found


def test_only_transition_scan_gates_reach_scan_modules_from_core():
    assert core_edges_into(SCAN_SURFACE) == {("agent_ratchet.transition_scan", Level.PHP),
                                             ("agent_ratchet.transition_scan", Level.MAGENTO)}
