"""Drop repeated PHP/Magento findings; lives in core so the scan modules load only behind their profile gates."""

from __future__ import annotations

from collections.abc import Sequence

from agent_ratchet.git_guard_io import SlopViolation

PHP_CATEGORY_PREFIX = "php_"
DEDUPED_PREFIXES: tuple[str, ...] = (PHP_CATEGORY_PREFIX, "magento_")


def dedupe_php_violations(violations: Sequence[SlopViolation]) -> list[SlopViolation]:
    """Drop repeated PHP/Magento findings (per-commit and aggregate runs see the same change); others are untouched."""
    seen: set[tuple[str, str, str, str]] = set()
    out: list[SlopViolation] = []
    for v in violations:
        if v.category.startswith(DEDUPED_PREFIXES):
            key = (v.file, v.category, v.message, v.snippet)
            if key in seen:
                continue
            seen.add(key)
        out.append(v)
    return out
