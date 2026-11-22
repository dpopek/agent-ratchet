"""Import edges of one module, each tagged with the recognised gate that dominates it (spec §6.5 items 2–3)."""

from __future__ import annotations

import ast
from dataclasses import dataclass

from .gating import (LOADER, LOADER_MODULE, PREDICATE, PREDICATE_MODULE, GateSite, GateTrust, Level,
                     function_trust, gate_level, imported_once)

_UNTRUSTED = GateTrust(predicate_ok=False, bound_once=lambda name: False)


@dataclass(frozen=True)
class Edge:
    src: str
    dst: str
    level: Level   # the gate dominating the import; CORE when ungated
    lineno: int


def module_edges(module: str, tree: ast.Module, known: frozenset[str]) -> list[Edge]:
    return analyse(module, tree, known)[0]


def analyse(module: str, tree: ast.Module, known: frozenset[str]) -> tuple[list[Edge], list[GateSite]]:
    """The module's import edges and its trusted gate sites."""
    walker = _Walker(module, tree, known)
    walker.block(tree.body, Level.CORE, None, top=False)
    return walker.edges, walker.gates


class _Walker:
    def __init__(self, module: str, tree: ast.Module, known: frozenset[str]) -> None:
        self.module = module
        self.known = known
        self.predicate_ok = imported_once(tree, PREDICATE, PREDICATE_MODULE)
        self.loader_ok = imported_once(tree, LOADER, LOADER_MODULE)
        self.edges: list[Edge] = []
        self.gates: list[GateSite] = []

    def block(self, stmts: list[ast.stmt], level: Level, scope: tuple[str, GateTrust] | None, *, top: bool) -> None:
        """Walk a statement list; in a function's own top-level block a G-early gates every later statement."""
        current = level
        for stmt in stmts:
            self.stmt(stmt, current, scope)
            if top and scope is not None:
                gated = gate_level(stmt, early=True, trust=scope[1])
                if gated is not None:
                    self.gates.append(GateSite(self.module, scope[0], "early", gated, stmt.lineno))
                    current = max(current, gated)

    def stmt(self, node: ast.AST, level: Level, scope: tuple[str, GateTrust] | None) -> None:
        # Imports are statements, so expressions (lambda bodies included) can hold no edge and are not walked.
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            self.edges.extend(Edge(self.module, dst, level, node.lineno) for dst in self._targets(node))
            return
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            qual = f"{scope[0]}.{node.name}" if scope is not None else node.name
            trust = function_trust(node, predicate_ok=self.predicate_ok, loader_ok=self.loader_ok)
            self.block(node.body, Level.CORE, (qual, trust), top=True)   # a nested body starts ungated
            return
        if isinstance(node, ast.ClassDef):
            # The body runs at definition time (it inherits the level), but its names are not the function's,
            # so no gate is recognised inside it; methods get their own trust under the class's qualified name.
            qual = f"{scope[0]}.{node.name}" if scope is not None else node.name
            self.block(node.body, level, (qual, _UNTRUSTED), top=False)
            return
        if isinstance(node, ast.If) and scope is not None:
            gated = gate_level(node, early=False, trust=scope[1])
            if gated is not None:
                self.gates.append(GateSite(self.module, scope[0], "block", gated, node.lineno))
                self.block(node.body, max(level, gated), scope, top=False)
                self.block(node.orelse, level, scope, top=False)
                return
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.stmt, ast.ExceptHandler, ast.match_case)):
                self.stmt(child, level, scope)

    def _targets(self, node: ast.Import | ast.ImportFrom) -> list[str]:
        if isinstance(node, ast.Import):
            names = [a.name for a in node.names]
        elif node.level or not node.module:
            return []   # relative imports make the whole release core (closed world)
        else:
            names = [node.module, *(f"{node.module}.{a.name}" for a in node.names if a.name != "*")]
        out: list[str] = []
        for name in names:
            parts = name.split(".")
            for i in range(1, len(parts) + 1):
                prefix = ".".join(parts[:i])
                if prefix in self.known and prefix not in out:
                    out.append(prefix)
        return out
