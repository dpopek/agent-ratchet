"""Surface level of every module at one commit (spec §6.5 items 1–5)."""

from __future__ import annotations

import ast
from collections import deque
from dataclasses import dataclass
from typing import Mapping

from .closedworld import violations
from .gating import GateSite, Level
from .graph import Edge, analyse
from .tree import SourceTree, module_name

SURFACE_PACKAGES = ("agent_ratchet.php", "agent_ratchet.magento")
CLI_MODULE = "agent_ratchet.cli"
REGULAR_MODES = frozenset({"100644", "100755"})


@dataclass(frozen=True)
class SurfaceMap:
    commit: str
    level_of: Mapping[str, Level]
    all_core_reason: str | None   # set → the whole release counts as core
    gates: tuple[GateSite, ...]


def compute_surfaces(tree: SourceTree) -> SurfaceMap:
    parse_errors: list[str] = []
    unsupported = [f"unsupported entry {path} (mode {mode})"
                   for path, mode in sorted(tree.modes.items()) if mode not in REGULAR_MODES]
    paths: dict[str, list[str]] = {}
    for path in sorted(tree.files):
        name = module_name(path)
        if name is not None and tree.modes.get(path) in REGULAR_MODES:
            paths.setdefault(name, []).append(path)   # `a.py` and `a/__init__.py` both count for `a`
    known = frozenset(paths)

    found: list[str] = []
    edges: dict[str, list[Edge]] = {}
    gates: list[GateSite] = []
    for name in sorted(paths):
        for path in paths[name]:
            try:
                parsed = ast.parse(tree.files[path], filename=path)
            except (SyntaxError, ValueError) as exc:   # ValueError: null bytes on 3.11, undecodable source
                parse_errors.append(f"parse error {path}: {exc}")
                continue
            try:
                found.extend(violations(name, parsed))
                module_edges, module_gates = analyse(name, parsed, known)
            except RecursionError:
                parse_errors.append(f"parse error {path}: nesting too deep to analyse")
                continue
            edges.setdefault(name, []).extend(module_edges)
            gates.extend(module_gates)

    roots, missing = _roots(tree, known)
    reasons = [*parse_errors, *unsupported, *missing, *found]
    return SurfaceMap(
        commit=tree.commit,
        level_of=_levels(roots, edges, known),
        all_core_reason=reasons[0] if reasons else None,
        gates=tuple(sorted(gates, key=lambda g: (g.module, g.lineno, g.kind))),
    )


def _roots(tree: SourceTree, known: frozenset[str]) -> tuple[set[str], list[str]]:
    roots = {m for m in known if not any(m == p or m.startswith(p + ".") for p in SURFACE_PACKAGES)}
    missing: list[str] = []
    for script, target in sorted(tree.scripts.items()):
        mod = target.partition(":")[0].strip()
        if mod not in known:
            missing.append(f"missing root {mod} (script {script})")
            continue
        parts = mod.split(".")
        roots.update(p for p in (".".join(parts[:i]) for i in range(1, len(parts) + 1)) if p in known)
    if CLI_MODULE not in known:
        missing.append(f"missing root {CLI_MODULE}")
    return roots, missing


def _levels(roots: set[str], edges: Mapping[str, list[Edge]], known: frozenset[str]) -> dict[str, Level]:
    """core = closure of the roots over CORE edges; php = closure (over every edge) of the targets of PHP-gated
    edges, minus core; magento likewise, minus core and php. Only edges of modules reachable from the roots
    count, and anything left over is core. A module in both surfaces is PHP (magento implies php)."""
    core = _closure(roots, edges, only=Level.CORE)
    reachable = _closure(roots, edges)

    def surface(gate: Level) -> set[str]:
        targets = {e.dst for src in reachable for e in edges.get(src, ()) if e.level is gate}
        return _closure(targets, edges)

    php = surface(Level.PHP) - core
    magento = surface(Level.MAGENTO) - core - php
    return {m: Level.PHP if m in php else Level.MAGENTO if m in magento else Level.CORE for m in sorted(known)}


def _closure(starts: set[str], edges: Mapping[str, list[Edge]], only: Level | None = None) -> set[str]:
    seen = set(starts)
    work = deque(sorted(starts))
    while work:
        for edge in edges.get(work.popleft(), ()):
            if (only is None or edge.level is only) and edge.dst not in seen:
                seen.add(edge.dst)
                work.append(edge.dst)
    return seen
