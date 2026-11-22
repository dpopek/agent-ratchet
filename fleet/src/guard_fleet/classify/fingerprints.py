"""Predicate trust: AST fingerprints of the profile predicate and the loader's profile parsing (spec §6.5 item 6).

A target whose digest at P or at T is absent or not reviewed makes every consumer exposed to every surface.
Every new digest class needs a human review of the predicate before it goes into REVIEWED.
"""

from __future__ import annotations

import ast
from types import MappingProxyType
from typing import Mapping

from .canonical import canonical, digest
from .gating import bindings
from .surfaces import REGULAR_MODES
from .tree import SourceTree

FINGERPRINT_TARGETS: tuple[tuple[str, str], ...] = (
    ("src/agent_ratchet/php/scope.py", "php_profile_active"),
    ("src/agent_ratchet/git_guard_io.py", "parse_guard_config_bytes"),
    ("src/agent_ratchet/git_guard_io.py", "_parse_profile"),
    ("src/agent_ratchet/git_guard_io.py", "load_guard_config_for_ref"),
    ("src/agent_ratchet/git_guard_io.py", "_read_guard_config_for_ref"),
)

# Digests of `canonical(FunctionDef)` per target, computed from this repository's tags v4.0.0…v4.3.4 (identical
# on Python 3.11 and 3.15); each class matches a predicate version reviewed at planning time.
REVIEWED: Mapping[str, frozenset[str]] = MappingProxyType({
    "src/agent_ratchet/php/scope.py::php_profile_active": frozenset({
        # absent at v4.0.0–v4.0.1 (always a mismatch)
        "c2a1cdcd657d07b219e22c97417a2c0b2d487a3df4693f122a0d6062b7b215d1",   # v4.1.0–v4.3.4
    }),
    "src/agent_ratchet/git_guard_io.py::parse_guard_config_bytes": frozenset({
        "d371c2a0ac76b4b8aeedc048547bd59ea55caf9bb46c763bd1b526cc3a573200",   # v4.0.0–v4.0.1
        "cb01b060fc102bc304e3843f54dd54dc7bb8c420b41e266a07f456b5383997a3",   # v4.1.0–v4.1.4
        "f07592446d8c5702e7d87ede2baf0d3e60adf6c052693b1a5a607a9133a5cf1a",   # v4.2.0–v4.3.4
    }),
    "src/agent_ratchet/git_guard_io.py::_parse_profile": frozenset({
        "9a5fbef3653659173c0ebe6fcbb2e4f2ae2b907917628b43bb8826e0d9ea5ba1",   # v4.0.0–v4.3.4
    }),
    "src/agent_ratchet/git_guard_io.py::load_guard_config_for_ref": frozenset({
        "a1d769c4c16fd1547e6023d86170f16fe5b18f0fe438c60320b90f2db9ea1500",   # v4.0.0–v4.0.1
        "9de4f70260fdd9ff1a23da046fe47e237603670fa7a93fd214c964baca8ac87b",   # v4.1.0–v4.3.4
    }),
    "src/agent_ratchet/git_guard_io.py::_read_guard_config_for_ref": frozenset({
        "a9820ea521f15fa308cd61e812f5a7634c8df672422cd95e0b0f18fe2db1c4a4",   # v4.0.0–v4.3.4
    }),
})


def target_id(path: str, name: str) -> str:
    return f"{path}::{name}"


def fingerprint(tree: SourceTree) -> dict[str, str | None]:
    """Digest of each target's module-level FunctionDef; None when the file or the function is absent, the file
    is no regular file or does not parse, or the name has any other binding in the module."""
    parsed: dict[str, ast.Module | None] = {}
    out: dict[str, str | None] = {}
    for path, name in FINGERPRINT_TARGETS:
        if path not in parsed:
            parsed[path] = _parse(tree, path)
        out[target_id(path, name)] = _digest_of(parsed[path], name)
    return out


def mismatches(tree: SourceTree) -> tuple[str, ...]:
    return tuple(target for target, value in fingerprint(tree).items()
                 if value is None or value not in REVIEWED.get(target, frozenset()))


def _parse(tree: SourceTree, path: str) -> ast.Module | None:
    raw = tree.files.get(path)
    if raw is None or tree.modes.get(path) not in REGULAR_MODES:
        return None
    try:
        return ast.parse(raw, filename=path)
    except (SyntaxError, ValueError, RecursionError):
        return None


def _digest_of(module: ast.Module | None, name: str) -> str | None:
    if module is None:
        return None
    defs = [stmt for stmt in module.body if isinstance(stmt, ast.FunctionDef) and stmt.name == name]
    try:
        found = list(bindings(ast.walk(module), name))
        if len(defs) != 1 or len(found) != 1 or found[0] is not defs[0]:
            return None
        return digest(canonical(defs[0]))
    except RecursionError:
        return None
