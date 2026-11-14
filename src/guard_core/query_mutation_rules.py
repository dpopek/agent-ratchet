#!/usr/bin/env python3
"""Zero-C5 query-mutation rules for Guard Core 2.3.3: assignment targets and mutating calls rooted at protected names."""

from __future__ import annotations

import ast

from guard_core.ast_refactoring_delta import MUTATING_COLLECTION_METHODS

CACHE_ATTRIBUTE_PREFIXES: tuple[str, ...] = ("_cache", "_lazy")


def mutation_chain_root(expr: ast.AST) -> tuple[str, str | None, int] | None:
    """Return (root name, attribute read directly off the root, chain depth) of an attribute/subscript chain.

    The chain stops at anything other than an attribute or subscript, so `self.make().a` has no Name root and
    is treated as a fresh object rather than protected state.
    """
    depth, first_attr = 0, None
    while isinstance(expr, (ast.Attribute, ast.Subscript)):
        first_attr = expr.attr if isinstance(expr, ast.Attribute) else None
        expr = expr.value
        depth += 1
    return (expr.id, first_attr, depth) if isinstance(expr, ast.Name) else None


def query_target_mutation_message(tgt: ast.AST, is_plain_assign: bool, receivers: set[str], params: set[str]) -> str | None:
    """Return the Zero-C5 message when an assignment target writes state reachable from a protected name."""
    root = mutation_chain_root(tgt)
    if root is None or root[2] == 0 or root[0] not in receivers | params:
        return None
    name, first_attr, depth = root
    if isinstance(tgt, ast.Subscript) and depth > 1 and name not in receivers:
        return None
    if is_plain_assign and name in receivers and first_attr is not None and first_attr.startswith(CACHE_ATTRIBUTE_PREFIXES):
        return None
    if depth == 1 and isinstance(tgt, ast.Attribute):
        return f"Query function mutates attribute '{name}.{tgt.attr}' (Zero-C5)."
    if depth == 1:
        return f"Query function mutates subscript on protected parameter '{name}' (Zero-C5)."
    if depth == 2 and isinstance(tgt, ast.Subscript) and first_attr is not None:
        return f"Query function mutates subscript on '{name}.{first_attr}' (Zero-C5)."
    return f"Query function mutates nested state '{ast.unparse(tgt)}' (Zero-C5)."


def query_call_mutation_message(node: ast.Call, callee: str, receivers: set[str], params: set[str]) -> str | None:
    """Return the Zero-C5 message when a call mutates state reachable from a protected name."""
    protected = receivers | params
    if callee in ("builtins.setattr", "builtins.delattr") and node.args and isinstance(node.args[0], ast.Name) and node.args[0].id in protected:
        return f"Query function mutates '{node.args[0].id}' via '{callee.split('.')[1]}()' (Zero-C5)."
    if not (isinstance(node.func, ast.Attribute) and node.func.attr in MUTATING_COLLECTION_METHODS):
        return None
    recv, method = node.func.value, node.func.attr
    if isinstance(recv, ast.Name):
        return f"Query function calls mutating method '{recv.id}.{method}()' (Zero-C5)." if recv.id in protected else None
    root = mutation_chain_root(recv)
    if root is None or root[0] not in receivers:
        return None
    if method == "setdefault" and root[1] is not None and root[1].startswith(CACHE_ATTRIBUTE_PREFIXES):
        return None
    return f"Query function calls mutating method '{ast.unparse(recv)}.{method}()' (Zero-C5)."
