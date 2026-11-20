"""Trusted Magento DI plugin-exception config (pure data validation, no optional deps)."""

from __future__ import annotations

from typing import Any

from agent_ratchet.ast_safety import GuardAnalysisError

MAGENTO_EXCEPTION_KEYS = frozenset({"area", "target", "plugin", "reason"})


def _valid_entry(entry: object) -> bool:
    if not isinstance(entry, dict) or set(entry) != MAGENTO_EXCEPTION_KEYS:
        return False
    return all(isinstance(v, str) and bool(v) for v in entry.values()) and bool(entry["reason"].strip())


def validate_magento_exceptions(value: object, source: str = "config") -> list[dict[str, str]]:
    if not isinstance(value, list):
        raise GuardAnalysisError(f"magento_di_exceptions must be a list at {source}")
    out: list[dict[str, str]] = []
    seen: set[tuple[Any, ...]] = set()
    for entry in value:
        if not _valid_entry(entry):
            raise GuardAnalysisError(f"Invalid magento_di_exceptions entry {entry!r} at {source}: need exactly area, target, plugin (non-empty str) and non-empty reason")
        item = {**entry, "target": entry["target"].lstrip("\\")}
        ident = (item["area"], item["target"], item["plugin"])
        if not item["target"]:
            raise GuardAnalysisError(f"Invalid magento_di_exceptions entry {entry!r} at {source}: empty target")
        if ident in seen:
            raise GuardAnalysisError(f"Duplicate magento_di_exceptions entry {ident!r} at {source}")
        seen.add(ident)
        out.append(item)
    return out
