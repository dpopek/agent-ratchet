"""Rewrite of the one agent-ratchet pin line in a consumer's requirements or pyproject file."""

from __future__ import annotations

import re

PIN_PREFIX = (rb"(?:guard-core|agent-ratchet)(?:\[[a-z,]+\])? @ "
              rb"git\+https://github\.com/dpopek/(?:guard-core|agent-ratchet)@")
_SHA = re.compile(r"[0-9a-f]{40}")


class PinError(Exception):
    """The pin file does not hold exactly one pin line for the expected SHA."""


def rewrite_pin(text: bytes, p: str, t: str) -> bytes:
    """Replace the 40 SHA bytes of the single pin line for `p`; every other byte stays."""
    if not (_SHA.fullmatch(p) and _SHA.fullmatch(t)):
        raise PinError(f"not a 40-hex SHA: {p[:8]!r} or {t[:8]!r}")
    matches = list(re.finditer(PIN_PREFIX + p.encode() + rb"(?![0-9a-f])", text))
    if len(matches) != 1:
        raise PinError(f"{len(matches)} pin lines for {p[:8]}")
    end = matches[0].end()
    return text[:end - len(p)] + t.encode() + text[end:]


def pin_test_hardcodes(text: bytes, p: str) -> bool:
    """True when the pin test file holds `p` as a literal (the fleet does not rewrite test files)."""
    return p.encode() in text
