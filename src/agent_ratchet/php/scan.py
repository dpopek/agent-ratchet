"""PHP tamper rules inside a BASE/TARGET transition: entry pairing, trusted exceptions, cross-file test moves (spec R6/R8)."""

from __future__ import annotations

import os
import sys
from collections import Counter
from collections.abc import Mapping, Sequence
from typing import Any

from agent_ratchet.ast_safety import GuardAnalysisError
from agent_ratchet.git_guard_io import SlopViolation, git_cat_bytes
from agent_ratchet.php.scope import is_php_in_scope, php_profile_active

PHP_CATEGORY_PREFIX = "php_"
DEDUPED_PREFIXES: tuple[str, ...] = (PHP_CATEGORY_PREFIX, "magento_")


def _sort_key(v: SlopViolation) -> tuple[str, int, str, str]:
    return (v.file, v.line, v.category, v.message)


def pair_entries(entries: Sequence[tuple[str, str, str]], php_paths: Sequence[str]) -> list[tuple[str | None, str | None, bool]]:
    """(BASE path, TARGET path, renamed) per in-scope entry; a side that is absent or out of scope is None.

    R/C compare the old path's BASE against the new path's TARGET. A rename out of scope counts as a deletion of the
    old file, a move or copy into scope as a new file. `renamed` is True for an `R`/`C` entry paired on both sides.
    """
    pairs: list[tuple[str | None, str | None, bool]] = []
    for status, old, new in entries:
        old_in, new_in = is_php_in_scope(old, php_paths), is_php_in_scope(new, php_paths)
        if status.startswith("D"):
            base, target = (old if old_in else None), None
        elif status.startswith("A"):
            base, target = None, (new if new_in else None)
        elif status.startswith("C"):
            base, target = (old if old_in and new_in else None), (new if new_in else None)
        else:
            base, target = (old if old_in else None), (new if new_in else None)
        if base is not None or target is not None:
            pairs.append((base, target, status.startswith(("R", "C")) and base is not None and target is not None))
    return pairs


def _shadow_counts(path: str, analysis: Any) -> None:
    counts = Counter(f.kind for f in analysis.facts)
    detail = " ".join(f"{kind}={n}" for kind, n in sorted(counts.items())) or "none"
    print(f"agent-ratchet shadow: php {path}: {detail}", file=sys.stderr)


def php_transition_violations(
    entries: Sequence[tuple[str, str, str]],
    base_ref: str,
    target_prefix: str,
    base_cfg: Mapping[str, Any],
    cfg: Mapping[str, Any],
    cwd: str | None = None,
) -> list[SlopViolation]:
    """PHP findings for one transition; empty unless the TARGET config requests the php/magento profile.

    Trusted suppression exceptions come from the BASE config only (an entry added by the assessed change never
    applies). Under an external config both configs are the operator file, so it is the trust anchor for both refs.
    """
    if not php_profile_active(cfg):
        return []
    from agent_ratchet.php.compare import (
        REMOVED,
        analyze_pair,
        compare_php_analyses,
        compare_php_tests_across,
        php_test_delta,
    )
    from agent_ratchet.php.extract import TEST

    exceptions = base_cfg.get("php_suppression_exceptions", [])
    shadow = os.environ.get("AGENT_RATCHET_SHADOW") == "1"
    found: list[SlopViolation] = []
    removed_all: list[Any] = []
    added_all: list[Any] = []
    for base_path, target_path, renamed in pair_entries(entries, cfg.get("php_paths", ())):
        base_bytes = git_cat_bytes(f"{base_ref}:{base_path}", cwd) if base_path else None
        target_bytes = None
        if target_path:
            spec = f"{target_prefix}:{target_path}" if target_prefix else f":{target_path}"
            target_bytes = git_cat_bytes(spec, cwd)
            if target_bytes is None:
                raise GuardAnalysisError(f"Unable to read target git blob '{spec}'")
        if base_bytes is not None and base_bytes == target_bytes:
            continue
        path = target_path or base_path or ""
        base_an, target_an = analyze_pair(base_bytes, target_bytes, base_path, path)
        per_entry = compare_php_analyses(base_an, target_an, path, exceptions, renamed=renamed)
        found.extend(v for v in per_entry if v.category != REMOVED)  # removals are decided across all entries below
        if shadow and target_an is not None and target_path:
            _shadow_counts(target_path, target_an)
        if target_an is not None and target_an.decode_error:
            continue
        removed, added = php_test_delta(
            [f for f in (base_an.facts if base_an else ()) if f.kind == TEST],
            [f for f in (target_an.facts if target_an else ()) if f.kind == TEST],
        )
        removed_all.extend(removed)
        added_all.extend(added)
    found.extend(compare_php_tests_across(removed_all, added_all))
    return sorted(found, key=_sort_key)


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
