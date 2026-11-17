"""Canonical encoding and CanonicalFact v1 (shadow only)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_ratchet.facts.encoding import (
    ENCODING_VERSION,
    CanonicalEncodingError,
    canonical_bytes,
    canonical_map,
    context_hash,
    identity_hash,
    payload_hash,
)
from agent_ratchet.facts.model import CanonicalFact, Origin, index_facts

VECTORS = Path(__file__).parent / "golden" / "encoding" / "vectors.json"


def _fact(identity, payload, cardinality="unique_key", path="a/x.py"):
    return CanonicalFact("k", identity, payload, cardinality, "complete", Origin(path))


def test_encoding_version() -> None:
    assert ENCODING_VERSION == 1


def test_golden_vectors() -> None:
    entries = json.loads(VECTORS.read_text(encoding="utf-8"))
    assert len(entries) >= 17
    for entry in entries:
        assert canonical_bytes(entry["value"]).hex() == entry["bytes_hex"]
        assert identity_hash(entry["value"]) == entry["identity_sha256"]


def test_key_order_is_utf8_bytewise() -> None:
    assert canonical_bytes({"é": 1, "z": 2, "a": 3}) == '{"a":3,"z":2,"é":1}'.encode("utf-8")


def test_astral_vs_bmp_key_order_is_utf8_bytewise() -> None:
    # UTF-16 order would put the astral key first; UTF-8 byte order puts U+E000 first.
    assert canonical_bytes({"\U00010000": 1, "\ue000": 2}) == '{"\ue000":2,"\U00010000":1}'.encode("utf-8")


@pytest.mark.parametrize(
    "value",
    [1.0, float("nan"), float("inf"), {"a": object()}, {1: "x"}, "\ud800", {"\ud800": 1}, b"x", {"a": {1, 2}}],
)
def test_rejects(value) -> None:
    with pytest.raises(CanonicalEncodingError):
        canonical_bytes(value)


def test_tuple_is_list() -> None:
    assert canonical_bytes((1, "a")) == canonical_bytes([1, "a"])


def test_canonical_map_rejects_duplicates() -> None:
    with pytest.raises(CanonicalEncodingError):
        canonical_map([("a", 1), ("a", 1)])
    assert canonical_map([("a", 1), ("b", None)]) == {"a": 1, "b": None}


def test_bool_and_int_are_distinct() -> None:
    assert canonical_bytes(True) != canonical_bytes(1)
    assert identity_hash({"a": True}) != identity_hash({"a": 1})


def test_domain_separation() -> None:
    x = {"a": 1}
    assert len({identity_hash(x), payload_hash(x), context_hash(x)}) == 3


def test_multiset_keeps_identical_occurrences() -> None:
    facts = [_fact({"n": 1}, {"p": 1}, "multiset") for _ in range(3)]
    index = index_facts(facts)
    assert index.multiset[(facts[0].identity_hash, facts[0].payload_hash)] == 3
    assert not index.unique and not index.conflicts


def test_unique_same_identity_same_payload_dedups() -> None:
    index = index_facts([_fact({"n": 1}, {"p": 1}), _fact({"n": 1}, {"p": 1}, path="b/x.py")])
    assert len(index.unique) == 1 and not index.conflicts


def test_unique_conflict_produces_conflict_fact() -> None:
    a, b = _fact({"n": 1}, {"p": 1}), _fact({"n": 1}, {"p": 2})
    index = index_facts([a, b])
    assert index.unique == {}
    assert len(index.conflicts) == 1
    conflict = index.conflicts[0]
    assert conflict.kind == "agent-ratchet.duplicate_conflict"
    assert dict(conflict.identity) == {"of": a.identity_hash}


def test_moved_path_keeps_identity_changes_context() -> None:
    a, b = _fact({"n": 1}, {"p": 1}, path="a/x.py"), _fact({"n": 1}, {"p": 1}, path="b/x.py")
    assert a.identity_hash == b.identity_hash
    assert context_hash({"path": a.origin.path}) != context_hash({"path": b.origin.path})


def test_fact_validates_on_construction() -> None:
    with pytest.raises(CanonicalEncodingError):
        _fact({"n": 1.5}, {})


def test_identity_with_kind_key_is_rejected() -> None:
    with pytest.raises(CanonicalEncodingError):
        CanonicalFact("a", {"kind": "b", "n": 1}, {}, "unique_key", "complete", Origin("x"))
    b = CanonicalFact("b", {"n": 1}, {}, "unique_key", "complete", Origin("x"))
    assert b.identity_hash  # the colliding twin can no longer be built


def test_huge_int_is_encoding_error() -> None:
    with pytest.raises(CanonicalEncodingError):
        canonical_bytes(10**5000)


def test_cyclic_and_deep_structures_are_encoding_errors() -> None:
    cyclic: list = []
    cyclic.append(cyclic)
    with pytest.raises(CanonicalEncodingError):
        canonical_bytes(cyclic)
    deep: list = []
    for _ in range(100_000):
        deep = [deep]
    with pytest.raises(CanonicalEncodingError):
        canonical_bytes(deep)


@pytest.mark.parametrize("kwargs", [{"cardinality": "bogus"}, {"completeness": "partial"}])
def test_fact_rejects_bad_enums(kwargs) -> None:
    args = {"cardinality": "unique_key", "completeness": "complete", **kwargs}
    with pytest.raises(ValueError):
        CanonicalFact("k", {}, {}, origin=Origin("x"), **args)


@pytest.mark.parametrize("kind", ["", 5, None, "\ud800"])
def test_fact_rejects_bad_kind(kind) -> None:
    with pytest.raises(CanonicalEncodingError):
        CanonicalFact(kind, {}, {}, "unique_key", "complete", Origin("x"))


def test_fact_is_hashable_and_equal_by_content() -> None:
    a = _fact({"n": 1, "l": [1, {"x": 2}]}, {"p": 1})
    b = _fact({"l": [1, {"x": 2}], "n": 1}, {"p": 1})
    assert a == b and hash(a) == hash(b)
    assert len({a, b}) == 1
    assert a != _fact({"n": 2}, {"p": 1})
    assert a != _fact({"n": 1, "l": [1, {"x": 2}]}, {"p": 1}, path="b/x.py")
    assert a != "not a fact"


def test_fact_mappings_are_read_only_and_detached() -> None:
    ident = {"x": 0, "nested": {"y": [1, 2]}}
    payload = {"p": {"q": 1}}
    fact = _fact(ident, payload)
    before = (fact.identity_hash, fact.payload_hash)
    ident["x"] = 9
    ident["nested"]["y"].append(3)
    ident["nested"]["z"] = 1
    payload["p"]["q"] = 2
    assert (fact.identity_hash, fact.payload_hash) == before
    with pytest.raises(TypeError):
        fact.identity["x"] = 1  # type: ignore[index]
    with pytest.raises(TypeError):
        fact.identity["nested"]["y"] = 1  # type: ignore[index]
    with pytest.raises(TypeError):
        fact.payload["p"]["q"] = 1  # type: ignore[index]
    assert fact.identity["nested"]["y"] == (1, 2)


@pytest.mark.parametrize("field", ["identity", "payload"])
@pytest.mark.parametrize("bad", [["a"], "s", 1, None])
def test_non_mapping_identity_or_payload_raises_encoding_error(field, bad) -> None:
    kwargs = {"identity": {}, "payload": {}, field: bad}
    with pytest.raises(CanonicalEncodingError):
        CanonicalFact("k", cardinality="unique_key", completeness="complete", origin=Origin("x"), **kwargs)
