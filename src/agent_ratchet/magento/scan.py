"""Magento di.xml rules inside a BASE/TARGET transition: blob reads, DI side pairing and module removal (spec M4/M6)."""

from __future__ import annotations

import os
import sys
from collections.abc import Mapping, Sequence
from typing import Any

from agent_ratchet.ast_safety import GuardAnalysisError
from agent_ratchet.git_guard_io import SlopViolation, git_cat_bytes
from agent_ratchet.php.scope import DEFAULT_PHP_PATHS, is_in_scope

MODULE_MARKERS: tuple[str, ...] = ("/registration.php", "/etc/module.xml")


def _module_root(path: str, php_paths: Sequence[str]) -> str | None:
    """Module root of an in-scope module marker file, else None."""
    for marker in MODULE_MARKERS:
        if path.endswith(marker) and is_in_scope(path, php_paths, (marker,)):
            root = path[: -len(marker)]
            if any(root.startswith(p) for p in php_paths):
                return root
    return None


def removed_module_roots(entries: Sequence[tuple[str, str, str]], php_paths: Sequence[str]) -> frozenset[str]:
    """Roots whose registration.php or etc/module.xml is deleted, or renamed out of the root (name-status only)."""
    roots: set[str] = set()
    for status, old, new in entries:
        if not status.startswith(("D", "R")):
            continue
        root = _module_root(old, php_paths)
        if root is not None and (status.startswith("D") or not new.startswith(f"{root}/")):
            roots.add(root)
    return frozenset(roots)


def _di_pairs(
    entries: Sequence[tuple[str, str, str]], php_paths: Sequence[str]
) -> list[tuple[str | None, str | None]]:
    """(BASE path, TARGET path) per DI entry with `php.scan.pair_entries` D/A/R/C semantics; out-of-scope sides are None."""
    from agent_ratchet.magento.di import di_location

    pairs: list[tuple[str | None, str | None]] = []
    for status, old, new in entries:
        old_in, new_in = di_location(old, php_paths) is not None, di_location(new, php_paths) is not None
        if status.startswith("D"):
            base, target = (old if old_in else None), None
        elif status.startswith("A"):
            base, target = None, (new if new_in else None)
        elif status.startswith("C"):
            base, target = (old if old_in and new_in else None), (new if new_in else None)
        else:
            base, target = (old if old_in else None), (new if new_in else None)
        if base is not None or target is not None:
            pairs.append((base, target))
    return pairs


def _shadow_counts(path: str, analysis: Any) -> None:
    from agent_ratchet.magento.di import PLUGIN, PREFERENCE

    plugins = sum(1 for f in analysis.facts if f.kind == PLUGIN)
    preferences = sum(1 for f in analysis.facts if f.kind == PREFERENCE)
    print(f"agent-ratchet shadow: magento {path}: plugin={plugins} preference={preferences}", file=sys.stderr)


def magento_transition_violations(
    entries: Sequence[tuple[str, str, str]],
    base_ref: str,
    target_prefix: str,
    base_cfg: Mapping[str, Any],
    cfg: Mapping[str, Any],
    cwd: str | None = None,
) -> list[SlopViolation]:
    """Magento DI findings for one transition; empty unless the TARGET config requests the magento framework.

    Trusted exceptions come from the BASE config only. A byte-identical pair is skipped only when the area is also
    unchanged: a git rename from `etc/di.xml` to `etc/<area>/di.xml` with the same bytes still narrows the plugin.
    """
    if "magento" not in cfg.get("frameworks", ()):
        return []
    from agent_ratchet.magento.compare import DiSide, compare_di
    from agent_ratchet.magento.di import analyze_di, di_location

    php_paths = cfg.get("php_paths", DEFAULT_PHP_PATHS)
    base_sides: list[DiSide] = []
    target_sides: list[DiSide] = []
    shadow = os.environ.get("AGENT_RATCHET_SHADOW") == "1"
    for base_path, target_path in _di_pairs(entries, php_paths):
        base_loc = di_location(base_path, php_paths) if base_path else None
        target_loc = di_location(target_path, php_paths) if target_path else None
        base_bytes = git_cat_bytes(f"{base_ref}:{base_path}", cwd) if base_path else None
        target_bytes = None
        if target_path:
            spec = f"{target_prefix}:{target_path}" if target_prefix else f":{target_path}"
            target_bytes = git_cat_bytes(spec, cwd)
            if target_bytes is None:
                raise GuardAnalysisError(f"Unable to read target git blob '{spec}'")
        same_area = base_loc is not None and target_loc is not None and base_loc[1] == target_loc[1]
        if base_bytes is not None and base_bytes == target_bytes and same_area:
            continue
        if base_path and base_loc and base_bytes is not None:
            base_sides.append(DiSide(base_path, analyze_di(base_bytes, base_path, *base_loc)))
        if target_path and target_loc and target_bytes is not None:
            analysis = analyze_di(target_bytes, target_path, *target_loc)
            target_sides.append(DiSide(target_path, analysis))
            if shadow:
                _shadow_counts(target_path, analysis)
    removed = removed_module_roots(entries, php_paths)
    return compare_di(base_sides, target_sides, removed, base_cfg.get("magento_di_exceptions", []))
