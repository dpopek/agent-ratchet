"""Shared helpers for Magento adapter tests."""

from __future__ import annotations

import os

import pytest


def require_magento() -> None:
    """Skip when the magento extra is absent, unless AGENT_RATCHET_REQUIRE_EXTRAS=1 (then fail)."""
    if os.environ.get("AGENT_RATCHET_REQUIRE_EXTRAS") == "1":
        import defusedxml  # noqa: F401  (ImportError fails the test)
        import tree_sitter_php  # noqa: F401
        return
    pytest.importorskip("defusedxml")
    pytest.importorskip("tree_sitter_php")
