"""Analysis profile: which optional extras a repository's config requires, checked fail-closed."""

from __future__ import annotations

import importlib.util
from collections.abc import Mapping
from typing import Any

from agent_ratchet.git_guard_io import GuardAnalysisError

REQUIRED_MODULES: dict[str, tuple[str, ...]] = {
    "php": ("tree_sitter", "tree_sitter_php"),
    "magento": ("tree_sitter", "tree_sitter_php", "defusedxml"),
}
_ORDER = ("php", "magento")


def requested_profiles(cfg: Mapping[str, Any]) -> list[str]:
    wanted = set(cfg.get("languages", ())) | set(cfg.get("frameworks", ()))
    return [name for name in _ORDER if name in wanted]


def require_profile_capabilities(cfg: Mapping[str, Any]) -> None:
    """Raise GuardAnalysisError when a requested profile lacks its extra; php is checked before magento."""
    for name in requested_profiles(cfg):
        if any(importlib.util.find_spec(mod) is None for mod in REQUIRED_MODULES[name]):
            raise GuardAnalysisError(f"profile '{name}' requires agent-ratchet[{name}] (set EXTRAS={name} in guard.lock)")
