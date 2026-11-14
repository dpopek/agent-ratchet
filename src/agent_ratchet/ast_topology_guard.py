#!/usr/bin/env python3
"""Static module import graph resolver and Tarjan SCC cycle guard (Vector A2) for Guard Core 2.3.3."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import AbstractSet, Mapping, Sequence

from agent_ratchet.git_guard_io import (
    APP_CODE_PREFIXES,
    SELF_SKIP_NAMES,
    GuardAnalysisError,
    SlopViolation,
    is_test_filename,
)

_DEFAULT_IMPORT_ROOTS: tuple[str, ...] = (".", "src", "backend", "web", "mobile", "packages")


@dataclass(frozen=True)
class RawImportEntry:
    kind: str  # "import" | "from"
    module: str
    name: str
    level: int
    lineno: int


@dataclass(frozen=True)
class ModuleImportFacts:
    rel_path: str
    raw_imports: tuple[RawImportEntry, ...]
    defined_attrs: frozenset[str]
    has_dynamic_exports: bool


def _iter_target_names(target: ast.AST) -> list[str]:
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        out: list[str] = []
        for elt in target.elts:
            out.extend(_iter_target_names(elt))
        return out
    if isinstance(target, ast.Starred):
        return _iter_target_names(target.value)
    return []


def _is_type_checking_expr(expr: ast.AST, tc_bindings: Mapping[str, str]) -> tuple[bool, bool]:
    """Return (is_tc_guard, is_negated)."""
    if isinstance(expr, ast.UnaryOp) and isinstance(expr.op, ast.Not):
        ok, neg = _is_type_checking_expr(expr.operand, tc_bindings)
        return ok, not neg
    if isinstance(expr, ast.Name):
        return tc_bindings.get(expr.id) == "typing.TYPE_CHECKING", False
    if isinstance(expr, ast.Attribute) and isinstance(expr.value, ast.Name):
        return (
            tc_bindings.get(expr.value.id) == "module:typing" and expr.attr == "TYPE_CHECKING",
            False,
        )
    return False, False


class _ImportFactsVisitor(ast.NodeVisitor):
    def __init__(self, is_init_file: bool) -> None:
        self.is_init_file = is_init_file
        self.tc_bindings: dict[str, str] = {}
        self.raw_imports: list[RawImportEntry] = []
        self.defined_attrs: set[str] = set()
        self.imported_submodules: set[str] = set()
        self.has_dynamic_exports: bool = False
        self._at_top_level: bool = True

    def _bind_or_shadow(self, name: str, target: str) -> None:
        if target:
            self.tc_bindings[name] = target
        else:
            self.tc_bindings.pop(name, None)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            local = alias.asname or alias.name.split(".")[0]
            if alias.name in ("typing", "typing_extensions") and (alias.asname or "." not in alias.name):
                self._bind_or_shadow(local, "module:typing")
            else:
                self._bind_or_shadow(local, "")
            if self._at_top_level and self.is_init_file:
                self.defined_attrs.add(local)
            self.raw_imports.append(RawImportEntry("import", alias.name, alias.asname or "", 0, node.lineno))

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        mod = node.module or ""
        lvl = node.level or 0
        for alias in node.names:
            if alias.name == "*":
                if self.is_init_file:
                    self.has_dynamic_exports = True
                continue
            local = alias.asname or alias.name
            if lvl == 0 and mod in ("typing", "typing_extensions") and alias.name == "TYPE_CHECKING":
                self._bind_or_shadow(local, "typing.TYPE_CHECKING")
            else:
                self._bind_or_shadow(local, "")
            if self._at_top_level and self.is_init_file:
                if lvl == 1 and not mod:
                    self.imported_submodules.add(alias.name)
                elif lvl == 1 and mod == alias.name:
                    self.imported_submodules.add(local)
                else:
                    self.defined_attrs.add(local)
            self.raw_imports.append(RawImportEntry("from", mod, alias.name, lvl, node.lineno))

    def visit_If(self, node: ast.If) -> None:
        is_tc, is_neg = _is_type_checking_expr(node.test, self.tc_bindings)
        saved = dict(self.tc_bindings)
        if is_tc and not is_neg:
            for stmt in node.orelse:
                self.visit(stmt)
        elif is_tc and is_neg:
            for stmt in node.body:
                self.visit(stmt)
        else:
            for stmt in node.body:
                self.visit(stmt)
            self.tc_bindings = dict(saved)
            for stmt in node.orelse:
                self.visit(stmt)
        self.tc_bindings = saved

    def _visit_def_or_class(self, node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef) -> None:
        self._bind_or_shadow(node.name, "")
        if self._at_top_level and self.is_init_file:
            if node.name == "__getattr__":
                self.has_dynamic_exports = True
            else:
                self.defined_attrs.add(node.name)
        prev_top = self._at_top_level
        self._at_top_level = False
        saved = dict(self.tc_bindings)
        for stmt in node.body:
            self.visit(stmt)
        self.tc_bindings = saved
        self._at_top_level = prev_top

    visit_FunctionDef = _visit_def_or_class
    visit_AsyncFunctionDef = _visit_def_or_class
    visit_ClassDef = _visit_def_or_class

    def visit_Assign(self, node: ast.Assign) -> None:
        self.visit(node.value)
        for tgt in node.targets:
            if (
                self.is_init_file
                and isinstance(tgt, ast.Subscript)
                and isinstance(tgt.value, ast.Call)
                and isinstance(tgt.value.func, ast.Name)
                and tgt.value.func.id == "globals"
            ):
                self.has_dynamic_exports = True
            for name in _iter_target_names(tgt):
                self._bind_or_shadow(name, "")
                if self._at_top_level and self.is_init_file:
                    self.defined_attrs.add(name)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self.visit(node.value)
            for name in _iter_target_names(node.target):
                self._bind_or_shadow(name, "")
                if self._at_top_level and self.is_init_file:
                    self.defined_attrs.add(name)


def extract_module_import_facts(source: str, rel_path: str) -> ModuleImportFacts:
    try:
        tree = ast.parse(source, filename=rel_path)
    except SyntaxError as exc:
        raise GuardAnalysisError(f"{rel_path}:{exc.lineno or 1}: SyntaxError: {exc.msg}") from exc
    is_init = PurePosixPath(rel_path).name == "__init__.py"
    visitor = _ImportFactsVisitor(is_init_file=is_init)
    visitor.visit(tree)
    pure_attrs = frozenset(visitor.defined_attrs - visitor.imported_submodules)
    return ModuleImportFacts(
        rel_path=rel_path,
        raw_imports=tuple(visitor.raw_imports),
        defined_attrs=pure_attrs,
        has_dynamic_exports=visitor.has_dynamic_exports,
    )


def _build_dotted_lookup(
    all_paths: AbstractSet[str],
    import_roots: Sequence[str],
) -> tuple[dict[str, str], dict[str, str]]:
    """Return (module_dotted_to_path, package_dotted_to_init_path)."""
    roots = list(_DEFAULT_IMPORT_ROOTS)
    for r in import_roots:
        norm = r.strip("/").strip() or "."
        if norm not in roots:
            roots.append(norm)
    mod_map: dict[str, str] = {}
    pkg_map: dict[str, str] = {}
    for rel in sorted(all_paths):
        if not rel.endswith(".py"):
            continue
        p = PurePosixPath(rel)
        for root in roots:
            if root == ".":
                rel_parts = list(p.parts)
            else:
                r_parts = list(PurePosixPath(root).parts)
                if list(p.parts[: len(r_parts)]) != r_parts:
                    continue
                rel_parts = list(p.parts[len(r_parts) :])
            if not rel_parts:
                continue
            if rel_parts[-1] == "__init__.py":
                pkg_parts = rel_parts[:-1]
                if pkg_parts:
                    dotted = ".".join(pkg_parts)
                    pkg_map.setdefault(dotted, rel)
                    mod_map.setdefault(dotted, rel)
            else:
                stem = rel_parts[-1][:-3]
                dotted = ".".join([*rel_parts[:-1], stem])
                mod_map.setdefault(dotted, rel)
    return mod_map, pkg_map


def _resolve_relative_base(rel_path: str, level: int, mod: str) -> str | None:
    p = PurePosixPath(rel_path)
    pkg_parts = list(p.parts[:-1])
    up = level - 1
    if up > len(pkg_parts):
        return None
    base_parts = pkg_parts[: len(pkg_parts) - up]
    if mod:
        base_parts.extend(mod.split("."))
    return ".".join(base_parts) if base_parts else ""


def _resolve_single_import_edges(
    caller_path: str,
    entry: RawImportEntry,
    facts_by_path: Mapping[str, ModuleImportFacts],
    mod_map: Mapping[str, str],
    pkg_map: Mapping[str, str],
) -> set[str]:
    edges: set[str] = set()
    if entry.kind == "import":
        parts = entry.module.split(".")
        for i in range(1, len(parts) + 1):
            prefix = ".".join(parts[:i])
            target = mod_map.get(prefix)
            if not target:
                continue
            if i < len(parts):
                if target == caller_path:
                    continue
                if target.endswith("/__init__.py") and caller_path.startswith(target[: -len("__init__.py")]):
                    continue
            edges.add(target)
        return edges

    base_dotted = (
        _resolve_relative_base(caller_path, entry.level, entry.module)
        if entry.level > 0
        else entry.module
    )
    if base_dotted is None:
        return edges

    base_target = mod_map.get(base_dotted) if base_dotted else None
    cand_dotted = f"{base_dotted}.{entry.name}" if base_dotted else entry.name
    child_target = mod_map.get(cand_dotted)
    if not child_target:
        if base_target:
            edges.add(base_target)
        return edges

    pkg_init = pkg_map.get(base_dotted) if base_dotted else None
    if pkg_init and pkg_init in facts_by_path:
        init_facts = facts_by_path[pkg_init]
        if entry.name in init_facts.defined_attrs or init_facts.has_dynamic_exports:
            if base_target:
                edges.add(base_target)
            return edges
    edges.add(child_target)
    return edges


def build_snapshot_import_graph(
    files_source_map: Mapping[str, str],
    import_roots: Sequence[str] = (),
) -> dict[str, set[str]]:
    facts_by_path: dict[str, ModuleImportFacts] = {}
    for rel, src in sorted(files_source_map.items()):
        if not rel.endswith(".py") or is_test_filename(rel) or PurePosixPath(rel).name in SELF_SKIP_NAMES:
            continue
        facts_by_path[rel] = extract_module_import_facts(src, rel)

    mod_map, pkg_map = _build_dotted_lookup(set(facts_by_path), import_roots)
    graph: dict[str, set[str]] = {rel: set() for rel in facts_by_path}
    for rel, facts in facts_by_path.items():
        for entry in facts.raw_imports:
            graph[rel].update(_resolve_single_import_edges(rel, entry, facts_by_path, mod_map, pkg_map))
    return graph


def tarjan_scc(graph: Mapping[str, AbstractSet[str]]) -> list[set[str]]:
    index = 0
    indices: dict[str, int] = {}
    lowlink: dict[str, int] = {}
    stack: list[str] = []
    on_stack: set[str] = set()
    cycles: list[set[str]] = []

    def strongconnect(node: str) -> None:
        nonlocal index
        indices[node] = index
        lowlink[node] = index
        index += 1
        stack.append(node)
        on_stack.add(node)
        for nbr in sorted(graph.get(node, ())):
            if nbr not in graph:
                continue
            if nbr not in indices:
                strongconnect(nbr)
                lowlink[node] = min(lowlink[node], lowlink[nbr])
            elif nbr in on_stack:
                lowlink[node] = min(lowlink[node], indices[nbr])
        if lowlink[node] == indices[node]:
            scc: set[str] = set()
            while True:
                w = stack.pop()
                on_stack.remove(w)
                scc.add(w)
                if w == node:
                    break
            if len(scc) > 1 or node in graph.get(node, ()):
                cycles.append(scc)

    for v in sorted(graph):
        if v not in indices:
            strongconnect(v)
    return cycles


def find_import_cycles(root_dir: Path, import_roots: Sequence[str] = ()) -> list[list[str]]:
    files_map: dict[str, str] = {}
    for p in sorted(root_dir.rglob("*.py")):
        if ".git" in p.parts:
            continue
        rel = p.relative_to(root_dir).as_posix()
        if rel.startswith(APP_CODE_PREFIXES) and not is_test_filename(rel):
            files_map[rel] = p.read_text(encoding="utf-8")
    sccs = tarjan_scc(build_snapshot_import_graph(files_map, import_roots=import_roots))
    return sorted(sorted(scc) for scc in sccs)


def compare_import_cycles(
    base_graph: Mapping[str, AbstractSet[str]],
    target_graph: Mapping[str, AbstractSet[str]],
    rename_map: Mapping[str, str] = (),
    target_import_lines: Mapping[str, int] = (),
) -> list[SlopViolation]:
    rmap = dict(rename_map)
    lines_map = dict(target_import_lines)
    renamed_base: dict[str, set[str]] = {}
    for u, nbrs in base_graph.items():
        u_new = rmap.get(u, u)
        renamed_base.setdefault(u_new, set()).update(rmap.get(v, v) for v in nbrs)

    base_scc_by_node: dict[str, set[str]] = {}
    for scc in tarjan_scc(renamed_base):
        for m in scc:
            base_scc_by_node[m] = scc

    target_scc_by_node: dict[str, set[str]] = {}
    for scc in tarjan_scc(target_graph):
        for m in scc:
            target_scc_by_node[m] = scc

    violations: list[SlopViolation] = []
    for m in sorted(target_graph):
        s_target = target_scc_by_node.get(m, {m})
        s_base = base_scc_by_node.get(m, {m} if m in renamed_base else set())
        new_self_loop = (m in target_graph.get(m, ())) and (m not in renamed_base.get(m, ()))
        new_or_expanded_scc = len(s_target) > 1 and (len(s_base) <= 1 or bool(s_target - s_base))
        if new_self_loop or new_or_expanded_scc:
            cycle_str = " <-> ".join(sorted(s_target))
            lineno = lines_map.get(m, 1)
            violations.append(
                SlopViolation(
                    m,
                    lineno,
                    "import_cycle",
                    f"Module '{m}' introduces or expands an import cycle SCC ({cycle_str}) (Zero-A2).",
                    cycle_str[:100],
                )
            )
    return violations
