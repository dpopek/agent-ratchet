"""PHPMD `@SuppressWarnings` docblock annotations (spec R4 "Declaration, PHPMD")."""

from __future__ import annotations

import re
from typing import Any

# PHPMD Node\Annotations / Node\Annotation matching [verified in spec R4, phpmd master 19.11].
_ANNOTATION = re.compile(r"@([a-z_][a-z0-9_]+)\(([^\)]+)\)", re.IGNORECASE)
_ALL_RULES = {"PHPMD", "PMD"}
DECLARATIONS = {
    "class_declaration",
    "interface_declaration",
    "trait_declaration",
    "enum_declaration",
    "method_declaration",
    "function_definition",
}


def annotations(comment: Any, source: bytes) -> list[tuple[tuple[str, ...], int]]:
    """(codes, 0-based row) for every `@SuppressWarnings(...)` in a `/**` docblock; `()` = all rules."""
    text = source[comment.start_byte : comment.end_byte].decode("utf-8", errors="replace")
    if not text.startswith("/**"):
        return []
    out: list[tuple[tuple[str, ...], int]] = []
    for m in _ANNOTATION.finditer(text):
        name = m.group(1)
        if name[:1].lower() + name[1:] != "suppressWarnings":
            continue
        value = m.group(2).strip('" ')
        codes = () if value in _ALL_RULES else (value,)
        out.append((codes, comment.start_point.row + text.count("\n", 0, m.start())))
    return out


def declaration_after(comment: Any) -> Any | None:
    """The class-like, method or function declaration the docblock precedes, else `None` (orphan)."""
    sib = comment.next_named_sibling
    while sib is not None and sib.type == "comment":
        sib = sib.next_named_sibling
    return sib if sib is not None and sib.type in DECLARATIONS else None
