"""Closed-world checks (spec §6.5 item 5): AST references that could load or rebind code past the import graph."""

from __future__ import annotations

import ast
from typing import Iterator

from .gating import PREDICATE_MODULE, bindings

FORBIDDEN_NAMES = frozenset({"__import__", "exec", "eval", "compile", "__builtins__", "setattr", "delattr",
                             "globals", "vars"})
FORBIDDEN_MODULES = frozenset({"builtins", "runpy", "pkgutil", "pydoc", "pickle"})
IMPORTLIB_OK = frozenset({"importlib.util.find_spec", "importlib.metadata.distribution",
                          "importlib.metadata.PackageNotFoundError"})
IMPORTLIB_MODS = frozenset({"importlib", "importlib.util", "importlib.metadata"})

FIND_SPEC = "importlib.util.find_spec"
_SYS_FORBIDDEN = frozenset({"sys.executable", "sys.modules"})
_TABLE_NODES = (ast.Constant, ast.Tuple, ast.List, ast.Set, ast.Dict, ast.Load)
_COMPREHENSIONS = (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)
_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)


def violations(module: str, tree: ast.Module) -> list[str]:
    """Every closed-world violation in `tree`, as `"<module>:L<n> <what>"`, ordered by line."""
    found = set(_Checker(tree).run())
    return [f"{module}:L{line} {what}" for line, what in sorted(found)]


class _Checker:
    def __init__(self, tree: ast.Module) -> None:
        self.tree = tree
        self.parents: dict[int, ast.AST] = {}
        for node in ast.walk(tree):
            for child in ast.iter_child_nodes(node):
                self.parents[id(child)] = node
        self.aliases = _aliases(tree)
        self.tables = self._literal_tables()
        self.called = {id(n.func) for n in ast.walk(tree) if isinstance(n, ast.Call)}

    def run(self) -> Iterator[tuple[int, str]]:
        for node in ast.walk(self.tree):
            line = getattr(node, "lineno", 0)
            if isinstance(node, ast.ImportFrom):
                yield from ((line, what) for what in _import_from(node))
            elif isinstance(node, ast.Import):
                yield from ((line, what) for what in _import(node))
            elif isinstance(node, ast.Name) and node.id in FORBIDDEN_NAMES:
                yield line, f"name {node.id}"
            if isinstance(node, (ast.Name, ast.Attribute)) and isinstance(node.ctx, ast.Load):
                yield from ((line, what) for full in self.resolve(node) for what in self._reference(node, full))
            if isinstance(node, (ast.Attribute, ast.Subscript)) and isinstance(node.ctx, (ast.Store, ast.Del)):
                yield from ((line, f"assignment to {full} attribute") for full in self._scope_targets(node))
            if isinstance(node, ast.Call) and FIND_SPEC in self.resolve(node.func) and not self._find_spec_ok(node):
                shown = ", ".join(ast.unparse(a) for a in [*node.args, *node.keywords]) or "(none)"
                yield line, f"find_spec argument {shown}"

    def resolve(self, node: ast.AST) -> set[str]:
        """Dotted names `node` can denote through the module's import aliases (flattened over every scope)."""
        attrs: list[str] = []
        while isinstance(node, ast.Attribute):
            attrs.append(node.attr)
            node = node.value
        if not isinstance(node, ast.Name):
            return set()
        tail = "".join(f".{a}" for a in reversed(attrs))
        return {base + tail for base in self.aliases.get(node.id, ())}

    def _reference(self, node: ast.AST, full: str) -> Iterator[str]:
        top = full.split(".")[0]
        if top in FORBIDDEN_MODULES:
            yield f"use of {full}"
        if full in _SYS_FORBIDDEN:
            yield full
        if top == "importlib" and full not in IMPORTLIB_MODS and full not in IMPORTLIB_OK:
            yield f"importlib member {full}"
        if full == FIND_SPEC and id(node) not in self.called:
            yield "find_spec reference without a call"

    def _scope_targets(self, node: ast.Attribute | ast.Subscript) -> Iterator[str]:
        base: ast.AST = node.value
        while True:
            for full in self.resolve(base):
                if full == PREDICATE_MODULE or full.startswith(PREDICATE_MODULE + "."):
                    yield full
            if not isinstance(base, (ast.Attribute, ast.Subscript)):
                return
            base = base.value

    # -- find_spec ----------------------------------------------------------------------------------

    def _find_spec_ok(self, call: ast.Call) -> bool:
        if len(call.args) != 1 or call.keywords:
            return False
        arg = call.args[0]
        if isinstance(arg, ast.Constant):
            return type(arg.value) is str and "." not in arg.value
        return isinstance(arg, ast.Name) and self._loops_over_table(call, arg.id)

    def _loops_over_table(self, call: ast.Call, name: str) -> bool:
        """`call` sits inside a loop or comprehension whose target `name` walks a trusted literal table,
        and nothing else binds `name` inside that loop."""
        child: ast.AST = call
        node = self.parents.get(id(call))
        while node is not None and not isinstance(node, _SCOPES):
            if isinstance(node, _COMPREHENSIONS):
                targets = [(g.target, g.iter) for g in node.generators]
                inside = not isinstance(child, ast.comprehension)  # the element, not a generator's iter/ifs
            elif isinstance(node, (ast.For, ast.AsyncFor)):
                targets = [(node.target, node.iter)]
                inside = any(child is stmt for stmt in node.body)
            else:
                targets, inside = [], False
            for target, it in targets:
                if inside and isinstance(target, ast.Name) and target.id == name and self._trusted_iter(it):
                    others = [b for b in bindings(ast.walk(node), name) if b is not target]
                    return not others
            child, node = node, self.parents.get(id(node))
        return False

    def _trusted_iter(self, it: ast.expr) -> bool:
        if isinstance(it, ast.Subscript) and isinstance(it.ctx, ast.Load):
            it = it.value
        return isinstance(it, ast.Name) and it.id in self.tables

    def _literal_tables(self) -> frozenset[str]:
        """Module-level names bound once to a table of undotted string literals, read only by subscript or loop."""
        out = set()
        for stmt in self.tree.body:
            if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
                name, value = stmt.targets[0].id, stmt.value
            elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name) and stmt.value is not None:
                name, value = stmt.target.id, stmt.value
            else:
                continue
            if _is_literal_table(value) and len(list(bindings(ast.walk(self.tree), name))) == 1 \
                    and all(self._read_only_use(n) for n in ast.walk(self.tree)
                            if isinstance(n, ast.Name) and n.id == name and isinstance(n.ctx, ast.Load)):
                out.add(name)
        return frozenset(out)

    def _read_only_use(self, use: ast.Name) -> bool:
        parent = self.parents.get(id(use))
        if isinstance(parent, ast.Subscript):
            return parent.value is use and isinstance(parent.ctx, ast.Load)
        if isinstance(parent, (ast.For, ast.AsyncFor, ast.comprehension)):
            return parent.iter is use
        return False


def _is_literal_table(value: ast.expr) -> bool:
    if not isinstance(value, (ast.Tuple, ast.List, ast.Set, ast.Dict)):
        return False
    for node in ast.walk(value):
        if not isinstance(node, _TABLE_NODES):
            return False
        if isinstance(node, ast.Constant) and not (type(node.value) is str and "." not in node.value):
            return False
    return True


def _aliases(tree: ast.Module) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.asname:
                    out.setdefault(a.asname, set()).add(a.name)
                else:
                    top = a.name.split(".")[0]
                    out.setdefault(top, set()).add(top)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            for a in node.names:
                if a.name != "*":
                    out.setdefault(a.asname or a.name, set()).add(f"{node.module}.{a.name}")
    return out


def _import(node: ast.Import) -> Iterator[str]:
    for a in node.names:
        top = a.name.split(".")[0]
        if top in FORBIDDEN_MODULES:
            yield f"import {a.name}"
        if top == "importlib" and a.name not in IMPORTLIB_MODS:
            yield f"import {a.name}"
        if (a.asname or top) in FORBIDDEN_NAMES:
            yield f"name {a.asname or top}"


def _import_from(node: ast.ImportFrom) -> Iterator[str]:
    if node.level:
        yield "relative import"
        return
    mod = node.module or ""
    top = mod.split(".")[0]
    for a in node.names:
        full = f"{mod}.{a.name}"
        if a.name == "*":
            if mod == "agent_ratchet" or mod.startswith("agent_ratchet."):
                yield f"star import from {mod}"
        elif (a.asname or a.name) in FORBIDDEN_NAMES:
            yield f"name {a.asname or a.name}"
        if full in _SYS_FORBIDDEN:
            yield f"import of {full}"
        if top == "importlib" and full not in IMPORTLIB_MODS and full not in IMPORTLIB_OK:
            yield f"importlib member {full}"
    if top in FORBIDDEN_MODULES:
        yield f"import {mod}"
