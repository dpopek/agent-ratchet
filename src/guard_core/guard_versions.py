#!/usr/bin/env python3
"""Guard Core 2.3.3 version registry: release order, per-version runtime file sets and default-branch selection."""

from __future__ import annotations

import subprocess

KNOWN_GUARD_VERSION_ORDER: tuple[str, ...] = ("2.0.0", "2.1.0", "2.2.0", "2.3.0", "2.3.1", "2.3.2", "2.3.3")
GUARD_VERSION: str = KNOWN_GUARD_VERSION_ORDER[-1]
AUTHORIZED_GUARD_VERSION_UPGRADES: frozenset[tuple[str, str]] = frozenset(zip(KNOWN_GUARD_VERSION_ORDER, KNOWN_GUARD_VERSION_ORDER[1:]))

# Runtime scanner file -> first Guard Core release that ships it. Historical manifests only list files of their own release.
RUNTIME_SCANNER_SINCE: dict[str, str] = {
    "scripts/audit/git_guard_io.py": "2.1.0",
    "scripts/audit/refactoring_guard.py": "2.0.0",
    "scripts/audit/ast_refactoring_delta.py": "2.1.0",
    "scripts/audit/ast_topology_guard.py": "2.1.0",
    "scripts/audit/ai_slop_scanner.py": "2.0.0",
    "scripts/audit/test_baseline_integrity.py": "2.0.0",
    "scripts/audit/cognitive_complexity.py": "2.3.0",
    "scripts/audit/guard_versions.py": "2.3.1",
    "scripts/audit/source_metrics.py": "2.3.2",
    "scripts/audit/query_mutation_rules.py": "2.3.3",
    "scripts/audit/ast_control_flow.py": "2.3.3",
    "scripts/audit/baseline_diff.py": "2.3.3",
}

DEFAULT_BRANCH_CANDIDATES: tuple[str, ...] = ("origin/main", "origin/master")
_UNREACHABLE_DISTANCE = 1 << 62


def required_runtime_files(guard_version: str) -> set[str]:
    """Runtime files a manifest of ``guard_version`` must hash; an unknown version requires all of them (fail closed)."""
    if guard_version not in KNOWN_GUARD_VERSION_ORDER:
        return set(RUNTIME_SCANNER_SINCE)
    rank = KNOWN_GUARD_VERSION_ORDER.index(guard_version)
    return {rel for rel, since in RUNTIME_SCANNER_SINCE.items() if KNOWN_GUARD_VERSION_ORDER.index(since) <= rank}


def _git_out(args: list[str], cwd: str | None) -> str | None:
    proc = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True)
    return proc.stdout.strip() if proc.returncode == 0 else None


def _distance_to_head(ref: str, cwd: str | None) -> int:
    out = _git_out(["rev-list", "--count", f"{ref}..HEAD"], cwd)
    return int(out) if out and out.isdigit() else _UNREACHABLE_DISTANCE


def default_remote_refs(cwd: str | None = None) -> list[str]:
    """Existing default-branch refs: the declared ``origin/HEAD`` first, then the others closest to HEAD first.

    A stale ``origin/master`` left behind after a rename to ``main`` is many commits behind HEAD, so it loses.
    """
    present = [ref for ref in DEFAULT_BRANCH_CANDIDATES if _git_out(["rev-parse", "--verify", "-q", f"{ref}^{{commit}}"], cwd)]
    declared = _git_out(["symbolic-ref", "-q", "--short", "refs/remotes/origin/HEAD"], cwd)
    ordered = sorted(present, key=lambda ref: (ref != declared, _distance_to_head(ref, cwd), DEFAULT_BRANCH_CANDIDATES.index(ref)))
    return ordered
