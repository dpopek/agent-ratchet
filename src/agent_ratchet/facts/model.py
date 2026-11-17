"""CanonicalFact v1 and the fact index used by shadow comparison."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Literal

from agent_ratchet.facts.encoding import canonical_bytes, identity_hash, payload_hash

Cardinality = Literal["unique_key", "multiset"]
Completeness = Literal["complete", "incomplete"]

DUPLICATE_CONFLICT_KIND = "agent-ratchet.duplicate_conflict"


@dataclass(frozen=True)
class Origin:
    path: str
    blob_oid: str | None = None
    byte_span: tuple[int, int] | None = None
    line: int | None = None


@dataclass(frozen=True)
class CanonicalFact:
    kind: str
    identity: Mapping
    payload: Mapping
    cardinality: Cardinality
    completeness: Completeness
    origin: Origin

    def __post_init__(self) -> None:
        canonical_bytes(self.identity)
        canonical_bytes(self.payload)

    @property
    def identity_hash(self) -> str:
        return identity_hash({"kind": self.kind, **self.identity})

    @property
    def payload_hash(self) -> str:
        return payload_hash(self.payload)


@dataclass
class FactIndex:
    unique: dict[str, CanonicalFact] = field(default_factory=dict)
    multiset: Counter[tuple[str, str]] = field(default_factory=Counter)
    conflicts: list[CanonicalFact] = field(default_factory=list)


def index_facts(facts: Iterable[CanonicalFact]) -> FactIndex:
    index = FactIndex()
    conflicted: dict[str, CanonicalFact] = {}
    for fact in facts:
        identity = fact.identity_hash
        if fact.cardinality == "multiset":
            index.multiset[(identity, fact.payload_hash)] += 1
            continue
        if identity in conflicted:
            continue
        existing = index.unique.get(identity)
        if existing is None:
            index.unique[identity] = fact
        elif existing.payload_hash != fact.payload_hash:
            del index.unique[identity]
            conflict = CanonicalFact(
                DUPLICATE_CONFLICT_KIND, {"of": identity}, {}, "unique_key", "complete", existing.origin
            )
            conflicted[identity] = conflict
            index.conflicts.append(conflict)
    return index
