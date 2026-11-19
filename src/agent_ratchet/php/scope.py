"""PHP analysis scope and trusted suppression-exception config (pure data validation, no optional deps)."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from agent_ratchet.ast_safety import GuardAnalysisError
from agent_ratchet.rel_path import clean_rel_segments

DEFAULT_PHP_PATHS: tuple[str, ...] = ("app/code/", "app/design/", "packages/", "src/")
PHP_EXTENSIONS: tuple[str, ...] = (".php", ".phtml")
EXCLUDED_SEGMENTS = frozenset({"vendor", "generated"})
EXCEPTION_KEYS = frozenset({"path", "symbol", "tool", "codes", "reason"})


def _valid_php_path(entry: object) -> bool:
    return isinstance(entry, str) and entry.endswith("/") and clean_rel_segments(entry[:-1])


def validate_php_paths(value: object, source: str = "config") -> list[str]:
    if not isinstance(value, list):
        raise GuardAnalysisError(f"php_paths must be a list at {source}")
    for entry in value:
        if not _valid_php_path(entry):
            raise GuardAnalysisError(f"Invalid php_paths entry {entry!r} at {source}: need a repo-relative directory ending in '/'")
    if len(set(value)) != len(value):
        raise GuardAnalysisError(f"Duplicate php_paths entry at {source}")
    return list(value)


def _valid_exception_fields(entry: Mapping[str, Any]) -> bool:
    codes = entry["codes"]
    return (
        isinstance(entry["path"], str) and bool(entry["path"]) and clean_rel_segments(entry["path"])
        and isinstance(entry["symbol"], str) and bool(entry["symbol"]) and isinstance(entry["tool"], str) and bool(entry["tool"])
        and isinstance(codes, list) and all(isinstance(c, str) and c for c in codes)
        and isinstance(entry["reason"], str) and bool(entry["reason"].strip())
    )


def validate_exceptions(value: object, source: str = "config") -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise GuardAnalysisError(f"php_suppression_exceptions must be a list at {source}")
    out: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    for entry in value:
        if not isinstance(entry, dict) or set(entry) != EXCEPTION_KEYS or not _valid_exception_fields(entry):
            raise GuardAnalysisError(
                f"Invalid php_suppression_exceptions entry {entry!r} at {source}: need exactly path, symbol, tool, codes (list of str), non-empty reason"
            )
        item = {**entry, "codes": sorted(entry["codes"])}
        ident = (item["path"], item["symbol"], item["tool"], tuple(item["codes"]))
        if ident in seen:
            raise GuardAnalysisError(f"Duplicate php_suppression_exceptions entry {ident!r} at {source}")
        seen.add(ident)
        out.append(item)
    return out


def is_php_in_scope(path: str, php_paths: Sequence[str]) -> bool:
    if not path.endswith(PHP_EXTENSIONS) or not any(path.startswith(p) for p in php_paths):
        return False
    return not EXCLUDED_SEGMENTS.intersection(path.split("/")[:-1])


def php_profile_active(cfg: Mapping[str, Any]) -> bool:
    return "php" in cfg.get("languages", ()) or "magento" in cfg.get("frameworks", ())
