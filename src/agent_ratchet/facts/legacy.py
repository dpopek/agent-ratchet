"""Adapter between legacy SlopViolation records and CanonicalFact (shadow mode only)."""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence

from agent_ratchet.facts.model import CanonicalFact, Origin
from agent_ratchet.git_guard_io import SlopViolation

_LEGACY_PREFIX = "legacy."


def violation_to_fact(v: SlopViolation) -> CanonicalFact:
    return CanonicalFact(
        kind=f"{_LEGACY_PREFIX}{v.category}",
        identity={"file": v.file, "line": v.line, "category": v.category},
        payload={"message": v.message, "snippet": v.snippet},
        cardinality="multiset",
        completeness="complete",
        origin=Origin(path=v.file, line=v.line),
    )


def fact_to_violation(f: CanonicalFact) -> SlopViolation:
    return SlopViolation(
        f.identity["file"], f.identity["line"], f.identity["category"], f.payload["message"], f.payload["snippet"]
    )


def shadow_report(violations: Sequence[SlopViolation]) -> str:
    facts = [violation_to_fact(v) for v in violations]
    parity = Counter(fact_to_violation(f) for f in facts) == Counter(violations)
    return f"agent-ratchet shadow: {len(facts)} facts, parity {'ok' if parity else 'MISMATCH'}"
