"""Fleet exit codes and the exceptions that map to them."""

from __future__ import annotations

from enum import IntEnum
from typing import Iterable


class FleetExit(IntEnum):
    OK = 0
    BLOCKED = 1
    USAGE = 2
    SHA_MISMATCH = 3
    CANCELLED = 4
    NO_HELPER = 5
    FAILED = 6


class UsageError(Exception):
    """Usage, config, target or self-check problem: exit 2, the message is printed."""


class Cancelled(Exception):
    """Confirmation cancelled or timed out: exit 4."""


class NoHelper(Exception):
    """No confirmation helper available (needs macOS with swiftc): exit 5."""


_PRECEDENCE = (FleetExit.FAILED, FleetExit.CANCELLED, FleetExit.BLOCKED, FleetExit.NO_HELPER)


def combine(codes: Iterable[FleetExit]) -> FleetExit:
    """Fold per-consumer codes into one run code (FAILED > CANCELLED > BLOCKED > NO_HELPER > OK)."""
    seen = set(codes)
    ending = seen & {FleetExit.USAGE, FleetExit.SHA_MISMATCH}
    if ending:
        raise ValueError(f"{sorted(ending)} end a run at once and cannot be combined")
    for code in _PRECEDENCE:
        if code in seen:
            return code
    return FleetExit.OK
