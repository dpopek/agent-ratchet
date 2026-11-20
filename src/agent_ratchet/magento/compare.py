"""BASE vs TARGET comparison of di.xml plugin facts (disabled / removed / degraded)."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from agent_ratchet.facts.model import CanonicalFact
from agent_ratchet.git_guard_io import SlopViolation
from agent_ratchet.magento.di import PLUGIN, DiAnalysis

DISABLED = "magento_di_plugin_disabled"
REMOVED = "magento_di_plugin_removed"
DEGRADED = "magento_xml_degraded"

GLOBAL = "global"


@dataclass(frozen=True)
class DiSide:
    path: str
    analysis: DiAnalysis


@dataclass(frozen=True)
class _Entry:
    path: str
    line: int
    module_root: str
    area: str
    target: str
    name: str
    disabled: bool

    @property
    def subject(self) -> tuple[str, str]:
        return self.target, self.name

    @property
    def identity(self) -> tuple[str, str, str, str]:
        return self.module_root, self.area, self.target, self.name


def _entries(sides: Sequence[DiSide]) -> list[_Entry]:
    entries: list[_Entry] = []
    for side in sides:
        for fact in side.analysis.facts:
            if fact.kind == PLUGIN:
                entries.append(_entry(fact, side.path))
    return entries


def _entry(fact: CanonicalFact, path: str) -> _Entry:
    ident = fact.identity
    return _Entry(
        path,
        fact.origin.line or 1,
        ident["module_root"],
        ident["area"],
        ident["target"],
        ident["plugin_name"],
        bool(fact.payload["disabled"]),
    )


def _finding(category: str, verb: str, entry: _Entry) -> SlopViolation:
    snippet = f"{entry.area} {entry.target} {entry.name}"
    return SlopViolation(entry.path, entry.line, category, f"Magento DI plugin {verb}: {snippet}", snippet)


def _excepted(entry: _Entry, exceptions: Sequence[Mapping[str, str]]) -> bool:
    return any(
        e.get("area") == entry.area and e.get("target") == entry.target and e.get("plugin") == entry.name
        for e in exceptions
    )


def compare_di(
    base: Sequence[DiSide],
    target: Sequence[DiSide],
    removed_modules: frozenset[str],
    exceptions: Sequence[Mapping[str, str]],
) -> list[SlopViolation]:
    """Findings for one transition.

    DEGRADED: one per TARGET side whose analysis is unreadable (reason from that side).
    Unreadable BASE sides carry no facts, so no removal can be claimed from them.
    """
    found: set[SlopViolation] = set()
    base_entries, target_entries = _entries(base), _entries(target)

    base_disabled = {(e.area, *e.subject) for e in base_entries if e.disabled}
    target_identities = {e.identity for e in target_entries}
    target_active = {(e.area, *e.subject) for e in target_entries if not e.disabled}

    for entry in target_entries:
        if not entry.disabled or _excepted(entry, exceptions):
            continue
        if (entry.area, *entry.subject) in base_disabled or (GLOBAL, *entry.subject) in base_disabled:
            continue
        found.add(_finding(DISABLED, "disabled", entry))

    for entry in base_entries:
        if entry.disabled or entry.identity in target_identities or entry.module_root in removed_modules:
            continue
        if (entry.area, *entry.subject) in target_active or (GLOBAL, *entry.subject) in target_active:
            continue
        if _excepted(entry, exceptions):
            continue
        found.add(_finding(REMOVED, "removed", entry))

    for side in target:
        reason = side.analysis.unreadable
        if reason is not None:
            found.add(SlopViolation(side.path, 1, DEGRADED, f"Magento XML not analyzable ({reason})", reason))

    return sorted(found, key=lambda v: (v.file, v.line, v.category, v.message))
