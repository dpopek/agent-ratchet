"""Position-free canonical forms of ASTs and TOML values, and their digests."""

from __future__ import annotations

import ast
import hashlib

_DROPPED = frozenset({"lineno", "col_offset", "end_lineno", "end_col_offset", "type_comment"})


def canonical(node: ast.AST) -> object:
    """`(type name, ((field, value)…))`, recursively; positions, type comments and empty fields are dropped.

    A falsy `is_lazy` (Python 3.15 adds it to Import/ImportFrom) is dropped too, so 3.11 and 3.15 digests agree.
    """
    return _canonical(node)


def _canonical(value: object) -> object:
    if isinstance(value, ast.AST):
        fields = []
        for name in value._fields:
            if name in _DROPPED:
                continue
            item = getattr(value, name, None)
            if item is None or item == [] or (name == "is_lazy" and not item):
                continue
            fields.append((name, _canonical(item)))
        return (type(value).__name__, tuple(fields))
    if isinstance(value, list):
        return tuple(_canonical(item) for item in value)
    return (type(value).__name__, value)


def digest(obj: object) -> str:
    return hashlib.sha256(repr(obj).encode("utf-8")).hexdigest()


def canonical_toml(value: object) -> object:
    """Type-tagged `(type name, value)` tuples, so `1`, `true` and `1.0` stay distinct; dict items sorted by key."""
    if isinstance(value, dict):
        return ("dict", tuple((key, canonical_toml(item)) for key, item in sorted(value.items(), key=lambda kv: kv[0])))
    if isinstance(value, list):
        return ("list", tuple(canonical_toml(item) for item in value))
    return (type(value).__name__, value)
