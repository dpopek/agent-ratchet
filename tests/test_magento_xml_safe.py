"""Tests for the bounded XML parser."""

from __future__ import annotations

import importlib
import sys

import pytest

from magento_support import require_magento


def _mod():
    require_magento()
    return importlib.import_module("agent_ratchet.magento.xml_safe")


def test_parses_plain_di():
    m = _mod()
    root = m.parse_xml(b'<?xml version="1.0"?><config><type name="A"/></config>')
    assert root.tag == "config"


def test_crlf_and_bom():
    m = _mod()
    root = m.parse_xml(b'\xef\xbb\xbf<config>\r\n<type name="A"/>\r\n</config>')
    assert root.tag == "config"


def _cases():
    return [
        (b'<!DOCTYPE x [<!ENTITY e "v">]><config>&e;</config>', "forbidden_construct"),
        (b'<!DOCTYPE x SYSTEM "http://e/x.dtd"><config/>', "forbidden_construct"),
        (b"<config>", "malformed"),
        (b"", "malformed"),
        (b"  \n", "malformed"),
        (b'<?xml version="1.0" encoding="ISO-8859-1"?><config/>', "malformed"),
        (b"<config>\xff</config>", "malformed"),
        (b"<a>" * 65 + b"</a>" * 65, "too_deep"),
        (b"<c>" + b"<t/>" * 50_000 + b"</c>", "too_many_nodes"),
        (b"<c>" + b" " * 1_048_576 + b"</c>", "too_large"),
    ]


@pytest.mark.parametrize(("blob", "reason"), _cases())
def test_rejects(blob, reason):
    m = _mod()
    with pytest.raises(m.XmlUnreadable) as exc:
        m.parse_xml(blob)
    assert exc.value.reason == reason


def test_depth_64_ok():
    m = _mod()
    assert m.parse_xml(b"<a>" * 64 + b"</a>" * 64).tag == "a"


def test_core_imports_without_extra(monkeypatch):
    monkeypatch.setitem(sys.modules, "defusedxml", None)
    monkeypatch.delitem(sys.modules, "agent_ratchet.magento.xml_safe", raising=False)
    mod = importlib.import_module("agent_ratchet.magento.xml_safe")
    assert hasattr(mod, "parse_xml")
