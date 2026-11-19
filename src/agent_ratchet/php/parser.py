"""PHP parsing via tree-sitter (lazy import) and a whitespace/comment-insensitive token hash."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from agent_ratchet.profile import require_profile_capabilities

NORM_DOMAIN = b"agent-ratchet:php-norm:v1\0"
_PARSER: Any = None  # lazy singleton, not thread-safe (the scanner is single-threaded)


@dataclass(frozen=True)
class ParsedPhp:
    tree: Any
    source: bytes
    error_spans: tuple[tuple[int, int], ...]


def _parser() -> Any:
    global _PARSER
    if _PARSER is None:
        require_profile_capabilities({"languages": ["php"]})
        import tree_sitter
        import tree_sitter_php

        _PARSER = tree_sitter.Parser(tree_sitter.Language(tree_sitter_php.language_php()))
    return _PARSER


def _error_spans(root: Any) -> tuple[tuple[int, int], ...]:
    spans: list[tuple[int, int]] = []
    if not root.has_error:
        return ()
    stack = [root]
    while stack:
        node = stack.pop()
        if node.type == "ERROR" or node.is_missing:
            spans.append((node.start_byte, node.end_byte))
        if node.has_error or node.is_missing:
            stack.extend(node.children)
    return tuple(sorted(spans))


def parse_php(blob: bytes) -> ParsedPhp:
    tree = _parser().parse(blob)
    return ParsedPhp(tree=tree, source=blob, error_spans=_error_spans(tree.root_node))


def node_text(node: Any, source: bytes) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _token(leaf: Any, source: bytes) -> bytes:
    tok = source[leaf.start_byte : leaf.end_byte]
    if leaf.type == "text":  # inline HTML: whitespace is not semantic
        tok = b" ".join(tok.split())
    return tok


def _leaf_tokens(node: Any, source: bytes) -> list[bytes]:
    tokens: list[bytes] = []
    stack = [node]
    while stack:
        cur = stack.pop()
        if cur.type == "comment":
            continue
        if cur.child_count == 0:
            tok = _token(cur, source)
            if tok:
                tokens.append(tok)
        else:
            stack.extend(reversed(cur.children))
    return tokens


def _digest(tokens: list[bytes]) -> str:
    h = hashlib.sha256(NORM_DOMAIN)
    h.update(b" ".join(tokens))
    return h.hexdigest()


def norm_hash(node: Any, source: bytes) -> str:
    """Hex SHA-256 over leaf tokens joined by one space; comments and whitespace never matter."""
    return _digest(_leaf_tokens(node, source))


EMPTY_LINE = "empty-line"  # fingerprint of a blank or comment-only row (never a hex digest)


def line_hash(root: Any, source: bytes, row: int) -> str:
    """`norm_hash` domain over non-comment leaf tokens that start on or span `row` (spec R4)."""
    tokens: list[bytes] = []
    stack = [root]
    while stack:
        cur = stack.pop()
        if cur.type == "comment" or cur.end_point.row < row or cur.start_point.row > row:
            continue
        if cur.child_count == 0:
            tok = _token(cur, source)
            if tok:
                tokens.append(tok)
        else:
            stack.extend(reversed(cur.children))
    return _digest(tokens) if tokens else EMPTY_LINE


def header_hash(node: Any, source: bytes) -> str:
    """`norm_hash` domain over a declaration's tokens except its `body` field (spec R4)."""
    body = node.child_by_field_name("body")
    tokens: list[bytes] = []
    for child in node.children:
        if body is not None and (child.start_byte, child.end_byte, child.type) == (
            body.start_byte,
            body.end_byte,
            body.type,
        ):
            continue
        tokens.extend(_leaf_tokens(child, source))
    return _digest(tokens)
