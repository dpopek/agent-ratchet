from __future__ import annotations

import pytest

from guard_fleet.lockfile import LockParseError, LockSpec, parse_lock, render_lock, spec_url

SHA = "0123456789abcdef0123456789abcdef01234567"
_B = SHA.encode("ascii")

# Mirrors the core's shared grammar table (bytes in, LockSpec or None for malformed).
CASES: list[tuple[bytes, LockSpec | None]] = [
    (_B, LockSpec(SHA)),
    (_B + b"\n", LockSpec(SHA)),
    (_B + b"\nEXTRAS=none", LockSpec(SHA, "none")),
    (_B + b"\nEXTRAS=none\n", LockSpec(SHA, "none")),
    (_B + b"\nEXTRAS=php\n", LockSpec(SHA, "php")),
    (_B + b"\nEXTRAS=php", LockSpec(SHA, "php")),
    (_B + b"\nEXTRAS=magento", LockSpec(SHA, "magento")),
    (_B + b"\nEXTRAS=magento\n", LockSpec(SHA, "magento")),
    (_B + b"\r\n", None),
    (_B + b" \n", None),
    (_B + b"\nEXTRAS=PHP", None),
    (_B + b"\nEXTRAS=", None),
    (_B + b"\nEXTRAS=php\nEXTRAS=php", None),
    (_B + b"\nEXTRAS=bogus\n", None),
    (_B + b"\nFOO=1", None),
    (_B + b"\n\n", None),
    (b"\xef\xbb\xbf" + _B, None),
    (b"A" * 40 + b"\n", None),
    (b"a" * 39 + b"\n", None),
    (b"", None),
]


@pytest.mark.parametrize("raw,expected", CASES)
def test_parse_lock(raw, expected):
    if expected is None:
        with pytest.raises(LockParseError):
            parse_lock(raw)
    else:
        assert parse_lock(raw) == expected


def test_parse_lock_error_is_value_error():
    assert issubclass(LockParseError, ValueError)


def test_lockspec_is_frozen():
    with pytest.raises(Exception):
        LockSpec(SHA).sha = "x"  # type: ignore[misc]


def test_render_lock_preserves_extras():
    assert render_lock("b" * 40, "php") == b"b" * 40 + b"\nEXTRAS=php\n"
    assert render_lock("b" * 40, "none") == b"b" * 40 + b"\n"


@pytest.mark.parametrize("extras", ["none", "php", "magento"])
def test_render_then_parse_round_trips(extras):
    assert parse_lock(render_lock(SHA, extras)) == LockSpec(SHA, extras)


def test_spec_url():
    base = "git+https://github.com/dpopek/agent-ratchet@" + SHA
    assert spec_url(SHA, "none") == "agent-ratchet @ " + base
    assert spec_url(SHA, "php") == "agent-ratchet[php] @ " + base
