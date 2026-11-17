"""Shared ``guard.lock`` grammar table: Python parser (test_lock_policy) and shell shim must agree on every row.

Each row is (raw file bytes, expected LockSpec); ``None`` means malformed.
"""

from __future__ import annotations

from agent_ratchet.lock_policy import LockSpec

SHA = "0123456789abcdef0123456789abcdef01234567"
_B = SHA.encode("ascii")

LOCK_GRAMMAR_CASES: list[tuple[bytes, LockSpec | None]] = [
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
    (_B + b"\nEXTRAS=php\n\n", None),
    (_B + b"\nEXTRAS =php", None),
    (_B + b"\nEXTRAS=php\r\n", None),
    (SHA.upper().encode("ascii") + b"\n", None),
    (_B[:39] + b"\n", None),
    (b" " + _B + b"\n", None),
    (_B + b"\n" + _B + b"\n", None),
    (b"", None),
]
