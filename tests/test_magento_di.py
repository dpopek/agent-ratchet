"""di.xml facts: location, plugins, preferences."""

from __future__ import annotations

import pytest
from magento_support import require_magento

from agent_ratchet.magento.di import PLUGIN, PREFERENCE, DiAnalysis, analyze_di, di_location

ROOT = "app/code/V/M"
PATH = f"{ROOT}/etc/di.xml"


def run(xml: str) -> DiAnalysis:
    require_magento()
    return analyze_di(xml.encode(), PATH, ROOT, "global")


def test_di_location():
    assert di_location("app/code/V/M/etc/di.xml", ["app/code/"]) == ("app/code/V/M", "global")
    assert di_location("app/code/V/M/etc/frontend/di.xml", ["app/code/"]) == ("app/code/V/M", "frontend")
    assert di_location("app/code/V/M/etc/a/b/di.xml", ["app/code/"]) is None
    assert di_location("vendor/x/etc/di.xml", ["vendor/"]) is None
    assert di_location("etc/di.xml", ["app/code/", ""]) is None
    assert di_location("app/code/V/M/etc/x/etc/di.xml", ["app/code/"]) == ("app/code/V/M/etc/x", "global")


def test_plugin_fact():
    a = run('<config><type name="\\A\\B"><plugin name="p" type="\\C" sortOrder="10"/></type></config>')
    assert a.unreadable is None
    (fact,) = a.facts
    assert fact.kind == PLUGIN
    assert dict(fact.identity) == {"module_root": ROOT, "area": "global", "target": "A\\B", "plugin_name": "p"}
    assert dict(fact.payload) == {"type": "C", "disabled": False, "sort_order": 10}
    assert (fact.cardinality, fact.completeness) == ("unique_key", "complete")
    assert fact.origin.path == PATH and fact.origin.line is None


@pytest.mark.parametrize(("value", "expected"), [("true", True), ("1", True), ("false", False), ("0", False), (None, False)])
def test_disabled_values(value, expected):
    attr = "" if value is None else f' disabled="{value}"'
    a = run(f'<config><type name="T"><plugin name="p" type="X"{attr}/></type></config>')
    assert a.unreadable is None
    assert a.facts[0].payload["disabled"] is expected


@pytest.mark.parametrize("value", ["yes", "True"])
def test_disabled_invalid(value):
    a = run(f'<config><type name="T"><plugin name="p" type="X" disabled="{value}"/></type></config>')
    assert a == DiAnalysis((), "malformed")


@pytest.mark.parametrize(
    "xml",
    [
        '<config><type name="T"><plugin type="X"/></type></config>',
        '<config><type><plugin name="p" type="X"/></type></config>',
        '<config><type name="T"><plugin name="p" sortOrder="x"/></type></config>',
        '<config><preference type="C"/></config>',
    ],
)
def test_malformed_shapes(xml):
    assert run(xml).unreadable == "malformed"


def test_negative_sort_order():
    a = run('<config><type name="T"><plugin name="p" type="X" sortOrder="-10"/></type></config>')
    assert a.facts[0].payload["sort_order"] == -10


def test_sort_order_trailing_newline_malformed():
    a = run('<config><type name="T"><plugin name="p" type="X" sortOrder="10&#10;"/></type></config>')
    assert a == DiAnalysis((), "malformed")


def test_missing_type_is_none():
    a = run('<config><type name="T"><plugin name="p"/></type><preference for="I"/></config>')
    assert a.unreadable is None
    by_kind = {f.kind: f for f in a.facts}
    assert by_kind[PLUGIN].payload["type"] is None
    assert by_kind[PREFERENCE].payload["type"] is None


def test_merge_later_wins():
    a = run(
        '<config><type name="T"><plugin name="p" type="X"/></type>'
        '<type name="T"><plugin name="p" disabled="true"/></type></config>'
    )
    (fact,) = a.facts
    assert fact.payload["type"] == "X" and fact.payload["disabled"] is True


def test_default_namespace():
    a = run('<config xmlns="urn:x"><type name="T"><plugin name="p" type="X"/></type></config>')
    assert [f.kind for f in a.facts] == [PLUGIN]


def test_comment_dropped():
    a = run('<config><type name="T"><!-- <plugin name="p" type="X"/> --></type></config>')
    assert a.facts == ()


def test_virtual_type_ignored():
    a = run('<config><virtualType name="V"><plugin name="p" type="X"/></virtualType></config>')
    assert a == DiAnalysis((), None)


def test_preference_fact():
    a = run('<config><preference for="\\I" type="\\C"/></config>')
    (fact,) = a.facts
    assert fact.kind == PREFERENCE
    assert dict(fact.identity) == {"module_root": ROOT, "area": "global", "for": "I"}
    assert dict(fact.payload) == {"type": "C"}


def test_unreadable_blob():
    assert run("<config>") == DiAnalysis((), "malformed")


def test_plugin_registered_once():
    require_magento()
    from agent_ratchet.facts.plugin import get_plugin

    plugin = get_plugin("magento")
    facts = plugin.extract(
        b'<config><preference for="I" type="C"/></config>', PATH, {"module_root": ROOT, "area": "adminhtml"}
    )
    assert facts[0].identity["area"] == "adminhtml"
