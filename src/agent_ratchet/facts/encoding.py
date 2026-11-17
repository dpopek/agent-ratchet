"""Deterministic canonical encoding and domain-separated hashes (encoding v1)."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
import hashlib
import json
from typing import Union

ENCODING_VERSION = 1

CanonicalValue = Union[str, int, bool, None, list["CanonicalValue"], dict[str, "CanonicalValue"]]

_IDENTITY_SEPARATOR = b"agent-ratchet:identity:v1\0"
_PAYLOAD_SEPARATOR = b"agent-ratchet:payload:v1\0"
_CONTEXT_SEPARATOR = b"agent-ratchet:context:v1\0"


class CanonicalEncodingError(ValueError):
    """Raised when a value cannot be canonically encoded."""


def _check_str(text: str) -> str:
    try:
        text.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise CanonicalEncodingError("string is not valid UTF-8 (lone surrogate)") from exc
    return text


def _normalise(value: object) -> object:
    if value is None or type(value) is bool:
        return value
    if type(value) is int:
        return value
    if isinstance(value, str):
        return _check_str(value)
    if isinstance(value, (list, tuple)):
        return [_normalise(item) for item in value]
    if isinstance(value, Mapping):
        keys = list(value)
        for key in keys:
            if not isinstance(key, str):
                raise CanonicalEncodingError(f"map key must be str, got {type(key).__name__}")
            _check_str(key)
        return {key: _normalise(value[key]) for key in sorted(keys, key=lambda k: k.encode("utf-8"))}
    raise CanonicalEncodingError(f"unsupported type for canonical encoding: {type(value).__name__}")


def canonical_bytes(value: CanonicalValue) -> bytes:
    """Encode ``value`` as compact UTF-8 JSON with dict keys in UTF-8 byte order."""
    try:
        return json.dumps(_normalise(value), ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except CanonicalEncodingError:
        raise
    except RecursionError as exc:
        raise CanonicalEncodingError("value is cyclic or nested too deeply") from exc
    except ValueError as exc:
        raise CanonicalEncodingError(f"value cannot be encoded: {exc}") from exc


def canonical_map(pairs: Iterable[tuple[str, CanonicalValue]]) -> dict[str, CanonicalValue]:
    """Build a dict from pairs, rejecting duplicate keys."""
    result: dict[str, CanonicalValue] = {}
    for key, value in pairs:
        if key in result:
            raise CanonicalEncodingError(f"duplicate key: {key!r}")
        result[key] = value
    return result


def _digest(separator: bytes, value: Mapping) -> str:
    return hashlib.sha256(separator + canonical_bytes(value)).hexdigest()


def identity_hash(identity: Mapping) -> str:
    return _digest(_IDENTITY_SEPARATOR, identity)


def payload_hash(payload: Mapping) -> str:
    return _digest(_PAYLOAD_SEPARATOR, payload)


def context_hash(context: Mapping) -> str:
    return _digest(_CONTEXT_SEPARATOR, context)
