"""Recognised profile gates: four exact `if` shapes, trusted only under strict binding rules (spec §6.5 item 3)."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from enum import IntEnum
from typing import Callable, Iterable, Iterator, Literal

PREDICATE = "php_profile_active"
PREDICATE_MODULE = "agent_ratchet.php.scope"
LOADER = "load_guard_config_for_ref"
LOADER_MODULE = "agent_ratchet.git_guard_io"

_TYPE_PARAMS = frozenset({"TypeVar", "ParamSpec", "TypeVarTuple"})


class Level(IntEnum):
    CORE = 0
    PHP = 1
    MAGENTO = 2


@dataclass(frozen=True)
class GateSite:
    module: str
    func: str
    kind: Literal["early", "block"]
    level: Level
    lineno: int


@dataclass(frozen=True)
class GateTrust:
    predicate_ok: bool                 # the module binds php_profile_active only by the trusted import
    bound_once: Callable[[str], bool]  # the gate argument is bound exactly once in the enclosing function


def gate_level(stmt: ast.stmt, *, early: bool, trust: GateTrust) -> Level | None:
    """The level `stmt` gates as a G-early (`early=True`) or a G-block, or None when it is no trusted gate."""
    if not isinstance(stmt, ast.If):
        return None
    test = stmt.test
    if early:
        if stmt.orelse or len(stmt.body) != 1 or not isinstance(stmt.body[0], ast.Return):
            return None
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            level, arg = Level.PHP, _predicate_arg(test.operand)
        else:
            level, arg = Level.MAGENTO, _magento_arg(test, ast.NotIn)
    else:
        level, arg = Level.PHP, _predicate_arg(test)
        if arg is None:
            level, arg = Level.MAGENTO, _magento_arg(test, ast.In)
    if arg is None or (level is Level.PHP and not trust.predicate_ok):
        return None
    return level if trust.bound_once(arg) else None


def _predicate_arg(node: ast.expr) -> str | None:
    """`php_profile_active(<Name>)` → the Name."""
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == PREDICATE
            and len(node.args) == 1 and not node.keywords and isinstance(node.args[0], ast.Name)):
        return node.args[0].id
    return None


def _magento_arg(node: ast.expr, op: type[ast.cmpop]) -> str | None:
    """`"magento" <op> <Name>.get("frameworks", ())` → the Name."""
    if not (isinstance(node, ast.Compare) and len(node.ops) == 1 and isinstance(node.ops[0], op)
            and len(node.comparators) == 1 and _is_str(node.left, "magento")):
        return None
    call = node.comparators[0]
    if not (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute) and call.func.attr == "get"
            and isinstance(call.func.value, ast.Name) and len(call.args) == 2 and not call.keywords
            and _is_str(call.args[0], "frameworks")
            and isinstance(call.args[1], ast.Tuple) and not call.args[1].elts):
        return None
    return call.func.value.id


def _is_str(node: ast.expr, text: str) -> bool:
    return isinstance(node, ast.Constant) and type(node.value) is str and node.value == text


# -- binding analysis --------------------------------------------------------------------------------

def bindings(nodes: Iterable[ast.AST], name: str) -> Iterator[ast.AST]:
    """Every node among `nodes` that binds `name` (an import binds through its alias node)."""
    for node in nodes:
        if isinstance(node, ast.Name):
            if node.id == name and isinstance(node.ctx, (ast.Store, ast.Del)):
                yield node
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.name == name:
                yield node
        elif isinstance(node, ast.arg):
            if node.arg == name:
                yield node
        elif isinstance(node, ast.Import):
            yield from (a for a in node.names if (a.asname or a.name.split(".")[0]) == name)
        elif isinstance(node, ast.ImportFrom):
            yield from (a for a in node.names if (a.asname or a.name) == name)
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            if name in node.names:
                yield node
        elif isinstance(node, ast.ExceptHandler):
            if node.name == name:
                yield node
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)):
            if node.name == name:
                yield node
        elif isinstance(node, ast.MatchMapping):
            if node.rest == name:
                yield node
        elif type(node).__name__ in _TYPE_PARAMS and getattr(node, "name", None) == name:
            yield node


def has_star_import(tree: ast.Module) -> bool:
    return any(isinstance(n, ast.ImportFrom) and any(a.name == "*" for a in n.names) for n in ast.walk(tree))


def imported_once(tree: ast.Module, name: str, module: str) -> bool:
    """`name` is bound solely by one module-level `from <module> import <name>` and never rebound."""
    if has_star_import(tree):
        return False
    trusted = {id(a) for stmt in tree.body
               if isinstance(stmt, ast.ImportFrom) and stmt.level == 0 and stmt.module == module
               for a in stmt.names if a.name == name and a.asname in (None, name)}
    found = list(bindings(ast.walk(tree), name))
    return len(found) == 1 and id(found[0]) in trusted


def _scope_nodes(body: list[ast.stmt]) -> Iterator[ast.AST]:
    """The nodes of one function scope; nested scopes contribute their name, the expressions evaluated here
    (decorators, defaults, annotations, bases) and any `nonlocal` that reaches back into this scope."""
    stack: list[ast.AST] = list(body)
    while stack:
        node = stack.pop()
        yield node
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            args = node.args
            stack.extend([*args.defaults, *(d for d in args.kw_defaults if d is not None)])
            if not isinstance(node, ast.Lambda):
                every_arg = [*args.posonlyargs, *args.args, *args.kwonlyargs, args.vararg, args.kwarg]
                stack.extend(a.annotation for a in every_arg if a is not None and a.annotation is not None)
                stack.extend(node.decorator_list)
                if node.returns is not None:
                    stack.append(node.returns)
                yield from _nonlocals(node.body)
            continue
        if isinstance(node, ast.ClassDef):
            stack.extend([*node.decorator_list, *node.bases, *node.keywords])
            yield from _nonlocals(node.body)
            continue
        stack.extend(ast.iter_child_nodes(node))


def _nonlocals(body: list[ast.stmt]) -> Iterator[ast.Nonlocal]:
    return (n for stmt in body for n in ast.walk(stmt) if isinstance(n, ast.Nonlocal))


def bound_once(func: ast.FunctionDef | ast.AsyncFunctionDef, name: str, *, loader_ok: bool) -> bool:
    """`name` is a parameter of `func`, or assigned once from a trusted loader call, and never rebound."""
    a = func.args
    good = [p.arg for p in (*a.posonlyargs, *a.args, *a.kwonlyargs)].count(name)
    bad = sum(1 for p in (a.vararg, a.kwarg) if p is not None and p.arg == name)
    nodes = list(_scope_nodes(func.body))
    from_loader: set[int] = set()
    annotation_only: set[int] = set()
    for node in nodes:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) \
                and node.targets[0].id == name and loader_ok and _is_loader_call(node.value):
            from_loader.add(id(node.targets[0]))
        elif isinstance(node, ast.AnnAssign) and node.value is None:
            annotation_only.add(id(node.target))
    for found in bindings(nodes, name):
        if id(found) in from_loader:
            good += 1
        elif id(found) not in annotation_only:
            bad += 1
    return good == 1 and bad == 0


def _is_loader_call(node: ast.expr) -> bool:
    return isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == LOADER


def function_trust(func: ast.FunctionDef | ast.AsyncFunctionDef, *, predicate_ok: bool, loader_ok: bool) -> GateTrust:
    return GateTrust(predicate_ok, lambda name: bound_once(func, name, loader_ok=loader_ok))
