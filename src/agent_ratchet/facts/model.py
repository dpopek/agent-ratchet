"""CanonicalFact v1 and the fact index used by shadow comparison."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Literal

from agent_ratchet.facts.encoding import CanonicalEncodingError, canonical_bytes, identity_hash, payload_hash

Cardinality = Literal["unique_key", "multiset"]
Completeness = Literal["complete", "incomplete"]

DUPLICATE_CONFLICT_KIND = "agent-ratchet.duplicate_conflict"


@dataclass(frozen=True)
class Origin:
    path: str
    blob_oid: str | None = None
    byte_span: tuple[int, int] | None = None
    line: int | None = None


def _freeze(value: Any) -> Any:
    """Deep read-only copy: Mapping -> MappingProxyType over a fresh dict, list/tuple -> tuple."""
    if isinstance(value, Mapping):
        return MappingProxyType({k: _freeze(v) for k, v in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(v) for v in value)
    return value


@dataclass(frozen=True, eq=False)
class CanonicalFact:
    kind: str
    identity: Mapping
    payload: Mapping
    cardinality: Cardinality
    completeness: Completeness
    origin: Origin

    def __post_init__(self) -> None:
        if not isinstance(self.kind, str) or not self.kind:
            raise CanonicalEncodingError("kind must be a non-empty str")
        canonical_bytes(self.kind)
        if self.cardinality not in ("unique_key", "multiset"):
            raise ValueError(f"invalid cardinality: {self.cardinality!r}")
        if self.completeness not in ("complete", "incomplete"):
            raise ValueError(f"invalid completeness: {self.completeness!r}")
        if not isinstance(self.identity, Mapping) or not isinstance(self.payload, Mapping):
            raise CanonicalEncodingError("identity and payload must be mappings")
        if "kind" in self.identity:
            raise CanonicalEncodingError('identity must not contain the reserved key "kind"')
        canonical_bytes(self.identity)
        canonical_bytes(self.payload)
        object.__setattr__(self, "identity", _freeze(self.identity))
        object.__setattr__(self, "payload", _freeze(self.payload))

    def _key(self) -> tuple:
        return (self.kind, self.identity_hash, self.payload_hash, self.cardinality, self.completeness, self.origin)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, CanonicalFact):
            return NotImplemented
        return self._key() == other._key()

    def __hash__(self) -> int:
        return hash(self._key())

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
