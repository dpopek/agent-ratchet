"""PHP parsing via tree-sitter (lazy import) and a whitespace/comment-insensitive token hash."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from agent_ratchet.profile import require_profile_capabilities

NORM_DOMAIN = b"agent-ratchet:php-norm:v1\0"
_PARSER: Any = None


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


def _leaf_tokens(node: Any, source: bytes) -> list[bytes]:
    tokens: list[bytes] = []
    stack = [node]
    while stack:
        cur = stack.pop()
        if cur.type == "comment":
            continue
        if cur.child_count == 0:
            if cur.end_byte > cur.start_byte:
                tokens.append(source[cur.start_byte : cur.end_byte])
        else:
            stack.extend(reversed(cur.children))
    return tokens


def norm_hash(node: Any, source: bytes) -> str:
    """Hex SHA-256 over leaf tokens joined by one space; comments and whitespace never matter."""
    h = hashlib.sha256(NORM_DOMAIN)
    h.update(b" ".join(_leaf_tokens(node, source)))
    return h.hexdigest()
