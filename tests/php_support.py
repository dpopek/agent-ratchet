"""Shared helpers for PHP adapter tests."""

from __future__ import annotations

import os

import pytest


def require_php() -> None:
    """Skip when the php extra is absent, unless AGENT_RATCHET_REQUIRE_EXTRAS=1 (then fail)."""
    if os.environ.get("AGENT_RATCHET_REQUIRE_EXTRAS") == "1":
        import tree_sitter_php  # noqa: F401  (ImportError fails the test)
        return
    pytest.importorskip("tree_sitter_php")
