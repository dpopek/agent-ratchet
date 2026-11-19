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
_TRANSPARENT = {"comment", "use_declaration"}  # trait `use` inside a class-like body


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


def _is_doc_comment(node: Any, source: bytes) -> bool:
    """A PHP T_DOC_COMMENT: `/**` followed by whitespace (`/**/` is a plain comment)."""
    head = source[node.start_byte : node.start_byte + 4]
    return head[:3] == b"/**" and head[3:].isspace()


def declaration_after(comment: Any, source: bytes) -> Any | None:
    """The declaration the docblock precedes, as PDepend attaches it (spec R4 "Precedes"), else `None`.

    Non-doc comments and trait `use` declarations are transparent (attributes belong to the
    declaration node); a later `/**` docblock wins, so this one is then an orphan.
    """
    sib = comment.next_named_sibling
    while sib is not None and sib.type in _TRANSPARENT:
        if sib.type == "comment" and _is_doc_comment(sib, source):
            return None
        sib = sib.next_named_sibling
    return sib if sib is not None and sib.type in DECLARATIONS else None
