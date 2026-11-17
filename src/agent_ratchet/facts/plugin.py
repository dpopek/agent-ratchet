"""LanguagePlugin protocol and registry (empty in 3.4.0; first adapter lands in 4.0)."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol

from agent_ratchet.facts.model import CanonicalFact


class LanguagePlugin(Protocol):
    name: str

    def extract(self, blob: bytes, path: str, ctx: Mapping[str, Any]) -> list[CanonicalFact]: ...


_REGISTRY: dict[str, LanguagePlugin] = {}


def register_plugin(plugin: LanguagePlugin) -> None:
    if plugin.name in _REGISTRY:
        raise ValueError(f"plugin already registered: {plugin.name!r}")
    _REGISTRY[plugin.name] = plugin


def get_plugin(name: str) -> LanguagePlugin:
    return _REGISTRY[name]


def registered_plugins() -> tuple[str, ...]:
    return tuple(sorted(_REGISTRY))
