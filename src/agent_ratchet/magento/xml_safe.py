"""Bounded, hardened XML parsing for Magento configuration files."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET

MAX_BYTES = 1_048_576
MAX_DEPTH = 64
MAX_NODES = 50_000

_DECL_ENCODING = re.compile(
    r"""^\s*<\?xml\b[^>]*?\bencoding\s*=\s*["']([^"']+)["']""", re.IGNORECASE
)


class XmlUnreadable(Exception):
    """The blob cannot be read safely; ``reason`` is a stable machine code."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def parse_xml(blob: bytes) -> ET.Element:
    """Parse ``blob`` with DTDs, entities and external references forbidden."""
    if len(blob) > MAX_BYTES:
        raise XmlUnreadable("too_large")
    try:
        text = blob.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise XmlUnreadable("malformed") from None
    declared = _DECL_ENCODING.match(text)
    if declared and declared.group(1).lower() not in ("utf-8", "utf8"):
        raise XmlUnreadable("malformed")

    import defusedxml  # lazy: the core must import without the magento extra
    import defusedxml.ElementTree as safe_et

    try:
        root = safe_et.fromstring(
            blob, forbid_dtd=True, forbid_entities=True, forbid_external=True
        )
    except defusedxml.DefusedXmlException:
        raise XmlUnreadable("forbidden_construct") from None
    except ET.ParseError:
        raise XmlUnreadable("malformed") from None

    _check_bounds(root)
    return root


def _check_bounds(root: ET.Element) -> None:
    nodes = 0
    stack = [(root, 1)]
    while stack:
        element, depth = stack.pop()
        nodes += 1
        if depth > MAX_DEPTH:
            raise XmlUnreadable("too_deep")
        if nodes > MAX_NODES:
            raise XmlUnreadable("too_many_nodes")
        stack.extend((child, depth + 1) for child in element)
