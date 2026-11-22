"""The ``guard.lock`` grammar (identical to the core's parser) and the pip spec it renders."""

from __future__ import annotations

import re
from dataclasses import dataclass

LOCK_RE = re.compile(rb"\A([0-9a-f]{40})(?:\nEXTRAS=(none|php|magento))?\n?\Z")
_SPEC_BASE = "git+https://github.com/dpopek/agent-ratchet"


@dataclass(frozen=True)
class LockSpec:
    sha: str
    extras: str = "none"


class LockParseError(ValueError):
    """The lock file does not match the grammar."""


def parse_lock(raw: bytes) -> LockSpec:
    match = LOCK_RE.match(raw)
    if match is None:
        raise LockParseError("malformed guard.lock")
    return LockSpec(match.group(1).decode("ascii"), (match.group(2) or b"none").decode("ascii"))


def render_lock(sha: str, extras: str) -> bytes:
    text = f"{sha}\n"
    if extras != "none":
        text += f"EXTRAS={extras}\n"
    return text.encode("ascii")


def spec_url(sha: str, extras: str) -> str:
    name = "agent-ratchet" if extras == "none" else f"agent-ratchet[{extras}]"
    return f"{name} @ {_SPEC_BASE}@{sha}"
