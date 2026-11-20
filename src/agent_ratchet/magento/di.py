"""di.xml facts: plugin and preference declarations, merged like Magento's DOM merge."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any
from xml.etree.ElementTree import Element

from agent_ratchet.facts.model import CanonicalFact, Origin
from agent_ratchet.facts.plugin import register_plugin, registered_plugins
from agent_ratchet.magento.xml_safe import XmlUnreadable, parse_xml
from agent_ratchet.php.scope import is_in_scope

PLUGIN = "magento.di.plugin"
PREFERENCE = "magento.di.preference"

_DI_PATH = re.compile(r"^(?P<root>.+)/etc/(?:(?P<area>[^/]+)/)?di\.xml$")
_INT = re.compile(r"^[0-9]+$")
_BOOLS = {"true": True, "1": True, "false": False, "0": False}


class _Malformed(Exception):
    pass


@dataclass(frozen=True)
class DiAnalysis:
    facts: tuple[CanonicalFact, ...]
    unreadable: str | None = None


def di_location(path: str, php_paths: Sequence[str]) -> tuple[str, str] | None:
    """Return ``(module_root, area)`` for an in-scope di.xml path, else ``None``."""
    if not is_in_scope(path, php_paths, (".xml",)):
        return None
    match = _DI_PATH.match(path)
    if match is None:
        return None
    return match["root"], match["area"] or "global"


def _local(tag: object) -> str:
    return tag.rsplit("}", 1)[-1] if isinstance(tag, str) else ""


def _fqcn(value: str | None) -> str | None:
    return None if value is None else value.removeprefix("\\")


def _required_name(element: Element, attr: str = "name") -> str:
    value = element.get(attr)
    if not value:
        raise _Malformed
    return value.removeprefix("\\")


def _collect(root: Element) -> tuple[dict[str, dict[str, dict[str, str]]], dict[str, dict[str, str]]]:
    plugins: dict[str, dict[str, dict[str, str]]] = {}
    preferences: dict[str, dict[str, str]] = {}
    for child in root:
        kind = _local(child.tag)
        if kind == "type":
            target = _required_name(child)
            declared = plugins.setdefault(target, {})
            for node in child:
                if _local(node.tag) == "plugin":
                    declared.setdefault(_required_name(node), {}).update(node.attrib)
        elif kind == "preference":
            preferences.setdefault(_required_name(child, "for"), {}).update(child.attrib)
    return plugins, preferences


def _disabled(attrs: Mapping[str, str]) -> bool:
    raw = attrs.get("disabled")
    if raw is None:
        return False
    if raw not in _BOOLS:
        raise _Malformed
    return _BOOLS[raw]


def _sort_order(attrs: Mapping[str, str]) -> int | None:
    raw = attrs.get("sortOrder")
    if raw is None:
        return None
    if not _INT.match(raw):
        raise _Malformed
    return int(raw)


def _facts(
    plugins: Mapping[str, Mapping[str, Mapping[str, str]]],
    preferences: Mapping[str, Mapping[str, str]],
    path: str,
    module_root: str,
    area: str,
) -> tuple[CanonicalFact, ...]:
    origin = Origin(path)
    where: dict[str, Any] = {"module_root": module_root, "area": area}
    facts: list[CanonicalFact] = []
    for target, declared in plugins.items():
        for name, attrs in declared.items():
            payload = {"type": _fqcn(attrs.get("type")), "disabled": _disabled(attrs), "sort_order": _sort_order(attrs)}
            identity = {**where, "target": target, "plugin_name": name}
            facts.append(CanonicalFact(PLUGIN, identity, payload, "unique_key", "complete", origin))
    for subject, attrs in preferences.items():
        facts.append(
            CanonicalFact(
                PREFERENCE, {**where, "for": subject}, {"type": _fqcn(attrs.get("type"))}, "unique_key", "complete", origin
            )
        )
    facts.sort(key=lambda f: (f.kind, f.identity_hash))
    return tuple(facts)


def analyze_di(blob: bytes, path: str, module_root: str, area: str) -> DiAnalysis:
    """Extract DI facts; unreadable or malformed input yields ``unreadable`` instead of raising."""
    try:
        root = parse_xml(blob)
        plugins, preferences = _collect(root)
        return DiAnalysis(_facts(plugins, preferences, path, module_root, area))
    except XmlUnreadable as exc:
        return DiAnalysis((), exc.reason)
    except _Malformed:
        return DiAnalysis((), "malformed")


class MagentoPlugin:
    name = "magento"

    def extract(self, blob: bytes, path: str, ctx: Mapping[str, Any]) -> list[CanonicalFact]:
        return list(analyze_di(blob, path, ctx["module_root"], ctx["area"]).facts)


if MagentoPlugin.name not in registered_plugins():
    register_plugin(MagentoPlugin())
