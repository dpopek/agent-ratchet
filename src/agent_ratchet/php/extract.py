"""PHP fact extraction (CanonicalFact v1, plugin name `php`; spec R3)."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from agent_ratchet.facts.model import CanonicalFact, Origin
from agent_ratchet.facts.plugin import register_plugin, registered_plugins
from agent_ratchet.php.directives import (
    FILE_SYMBOL,
    PhpDecodeError,
    collect,
    namespace_resolver,
    statement_hashes,
    symbol_path,
)
from agent_ratchet.php.parser import NORM_DOMAIN, ParsedPhp, parse_php
from agent_ratchet.php.phpunit import collect_tests

POINT, WINDOW, FILE = "php.suppression.point", "php.suppression.window", "php.suppression.file"
TEST, GAP = "php.test", "php.parse_gap"
_SYMBOL_NODES = frozenset(
    {"class_declaration", "interface_declaration", "trait_declaration", "enum_declaration", "method_declaration", "function_definition"}
)
_BUCKETS = ((0, "0"), (16, "<=16"), (256, "<=256"), (4096, "<=4096"))


@dataclass(frozen=True)
class Analysis:
    """Facts of one file, the normalized hash of every symbol that holds a parse gap, and every declared symbol path.

    `statement_hashes`: sorted window hash of every statement in the file; empty when the file has no window.
    """

    facts: tuple[CanonicalFact, ...]
    gap_hashes: Mapping[str, str]
    decode_error: bool = False
    symbols: frozenset[str] = frozenset()
    statement_hashes: tuple[str, ...] = ()


def _bucket(length: int) -> str:
    return next((label for limit, label in _BUCKETS if length <= limit), ">4096")


def _walk(node: Any):
    stack = [node]
    while stack:
        cur = stack.pop()
        yield cur
        stack.extend(reversed(cur.children))


def _raw_hash(node: Any, source: bytes) -> str:
    """Hash of a symbol's exact bytes: comments count, because directives and docblock tags live in them."""
    return hashlib.sha256(NORM_DOMAIN + b"raw\0" + source[node.start_byte : node.end_byte]).hexdigest()


def _file_hash(root: Any, source: bytes) -> str:
    """Hash of top-level code outside every class/function body (so edits inside symbols do not move it)."""
    h = hashlib.sha256(NORM_DOMAIN + b"file\0")
    pending = list(reversed(root.children))
    while pending:
        node = pending.pop()
        body = node.child_by_field_name("body") if node.type == "namespace_definition" else None
        if body is not None:
            pending.extend(reversed(body.children))
        elif node.type not in _SYMBOL_NODES:
            h.update(_raw_hash(node, source).encode())
    return h.hexdigest()


def _contains(node: Any, start: int, end: int) -> bool:
    # A zero-width span (a missing token) belongs to a symbol that ends exactly there.
    return node.start_byte <= start <= node.end_byte if start == end else node.start_byte <= start < node.end_byte


def _gaps(parsed: ParsedPhp) -> list[tuple[str, str, tuple[int, int]]]:
    """(symbol, normalized hash of that symbol, span) per ERROR/MISSING span; may raise PhpDecodeError."""
    root, source = parsed.tree.root_node, parsed.source
    nodes = [n for n in _walk(root) if n.type in _SYMBOL_NODES] if parsed.error_spans else []
    ns_at = namespace_resolver(root, source)
    file_hash: list[str] = []
    out: list[tuple[str, str, tuple[int, int]]] = []
    for start, end in parsed.error_spans:
        inside = [n for n in nodes if _contains(n, start, end)]
        node = min(inside, key=lambda n: n.end_byte - n.start_byte, default=None)
        if node is not None:
            out.append((symbol_path(node, source, ns_at(node.start_byte)), _raw_hash(node, source), (start, end)))
            continue
        file_hash = file_hash or [_file_hash(root, source)]
        out.append((FILE_SYMBOL, file_hash[0], (start, end)))
    return out


def _symbols(parsed: ParsedPhp) -> frozenset[str]:
    """Symbol path of every class-like, method and function declaration; may raise PhpDecodeError."""
    root, source = parsed.tree.root_node, parsed.source
    ns_at = namespace_resolver(root, source)
    return frozenset(symbol_path(n, source, ns_at(n.start_byte)) for n in _walk(root) if n.type in _SYMBOL_NODES)


def _gap_fact(path: str, symbol: str, bucket: str, origin: Origin) -> CanonicalFact:
    return CanonicalFact(GAP, {"path": path, "symbol": symbol}, {"bucket": bucket}, "multiset", "complete", origin)


def analyze(blob: bytes, path: str, blob_oid: str | None = None) -> Analysis:
    parsed = parse_php(blob)
    try:
        return _analyze(parsed, path, blob_oid)
    except PhpDecodeError:
        origin = Origin(path, blob_oid, (0, len(blob)), 1)
        return Analysis((_gap_fact(path, FILE_SYMBOL, "decode", origin),), {}, decode_error=True)


def _analyze(parsed: ParsedPhp, path: str, oid: str | None) -> Analysis:
    points, windows, files = collect(parsed)
    tests = [] if path.endswith(".phtml") else collect_tests(parsed, path)
    gaps = _gaps(parsed)
    hashes = {symbol: digest for symbol, digest, _ in gaps}

    def complete(symbol: str) -> str:
        bad = symbol in hashes or any(d != FILE_SYMBOL and symbol.startswith(d + "::") for d in hashes)
        return "incomplete" if bad else "complete"

    def at(line: int, span: tuple[int, int] | None = None) -> Origin:
        return Origin(path, oid, span, line)

    facts: list[CanonicalFact] = []
    for p in points:
        facts.append(
            CanonicalFact(
                POINT,
                {"path": path, "symbol": p.symbol, "tool": p.tool, "codes": list(p.codes)},
                {"anchor_ast_kind": p.anchor_kind, "anchor_norm_hash": p.anchor_hash}
                | ({"header_hash": p.header_hash} if p.tool == "phpmd" else {}),
                "multiset",
                complete(p.symbol),
                at(p.line),
            )
        )
    for w in windows:
        facts.append(
            CanonicalFact(
                WINDOW,
                {"path": path, "symbol": w.symbol, "tool": "phpcs", "codes": list(w.codes)},
                {"closed": w.closed, "statements": list(w.statements), "coverage": [list(c) for c in w.coverage]},
                "multiset",
                complete(w.symbol),
                at(w.line),
            )
        )
    for f in files:
        identity = {"path": path, "tool": f.tool, "codes": list(f.codes)}
        facts.append(CanonicalFact(FILE, identity, {}, "multiset", "complete", at(f.line)))
    for t in tests:
        identity = {"path": path, "class_fqn": t.class_fqn, "method": t.method}
        payload = {
            "assertions": t.assertions,
            "expects": t.expects,
            "expect_exception": list(t.expect_exception),
            "skips": t.skips,
            "incompletes": t.incompletes,
            "data_providers": list(t.data_providers),
            "abstract": t.abstract,
            "body_norm_hash": t.body_hash,  # in the payload hash, so removed/added tests pair only on the same body
        }
        symbol = f"{t.class_fqn}::{t.method}"
        facts.append(CanonicalFact(TEST, identity, payload, "unique_key", complete(symbol), at(t.line, t.span)))
    for symbol, _, (start, end) in gaps:
        line = parsed.source.count(b"\n", 0, start) + 1
        facts.append(_gap_fact(path, symbol, _bucket(end - start), at(line, (start, end))))
    facts.sort(key=lambda f: (f.kind, f.origin.line or 0, f.identity_hash, f.payload_hash))
    stmts = statement_hashes(parsed) if windows else ()
    return Analysis(tuple(facts), hashes, symbols=_symbols(parsed), statement_hashes=stmts)


class PhpPlugin:
    name = "php"

    def extract(self, blob: bytes, path: str, ctx: Mapping[str, Any]) -> list[CanonicalFact]:
        return list(analyze(blob, path, ctx.get("blob_oid")).facts)


if PhpPlugin.name not in registered_plugins():
    register_plugin(PhpPlugin())
