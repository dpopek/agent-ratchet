"""PHP suppression directives (phpstan, phpcs, psalm, phpmd) with anchors and windows (spec R3/R4).

Keyword and code-list parsing of one comment line lives in `directive_text`.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from agent_ratchet.php import phpmd
from agent_ratchet.php.codes import within
from agent_ratchet.php.directive_text import comment_lines, scan_line
from agent_ratchet.php.parser import (
    ParsedPhp,
    declaration_name_hash,
    header_hash,
    line_hash,
    norm_hash,
)

FILE_SYMBOL = "<file>"
_CLASS_LIKE = {"class_declaration", "interface_declaration", "trait_declaration", "enum_declaration"}
_CALLABLE = {"method_declaration", "function_definition"}
_ANONYMOUS = "anonymous_class"  # `new class {}`: its methods must not merge into an enclosing class
_NOT_ANCHORS = {"compound_statement", "namespace_definition"}
_PHP_TAGS = re.compile(rb"<\?(?:php)?(?=\s|$)|\?>", re.IGNORECASE)  # T_OPEN_TAG (not `<?=`) and T_CLOSE_TAG
_LINE_SCOPED = {"phpstan", "phpcs"}  # tools that ignore one line (spec R4 "Anchor hash")
_METRIC_WORDS = ("metrics", "complexity", "nesting")


class PhpDecodeError(ValueError):
    """An identifier in the PHP source is not valid UTF-8; the caller degrades the fact."""


@dataclass(frozen=True)
class PointSuppression:
    symbol: str
    tool: str
    codes: tuple[str, ...]
    anchor_kind: str | None
    anchor_hash: str | None
    line: int
    header_hash: str | None = None  # phpmd only: full declaration header, gates cross-symbol pairing
    row_scoped: bool = False  # anchor_hash fingerprints the ignored row, so the node kind is not compared (4.3.1 F1)


@dataclass(frozen=True)
class WindowSuppression:
    symbol: str
    codes: tuple[str, ...]
    closed: bool
    statements: tuple[str, ...]
    line: int
    rows: tuple[int, int] = (0, 0)  # covered rows [disable row, enable row or EOF) (spec R6, I2)


@dataclass(frozen=True)
class FileSuppression:
    tool: str
    codes: tuple[str, ...]
    line: int


@dataclass
class _Raw:
    """One directive occurrence inside a comment, before anchoring."""

    form: str  # point | disable | enable | file
    tool: str
    codes: tuple[str, ...]
    comment: Any
    line: int
    row_rule: str = ""  # see directive_text.scan_line


def _strict(source: bytes, start: int, end: int) -> str:
    try:
        return source[start:end].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PhpDecodeError("non-UTF-8 identifier in PHP source") from exc


def _ident(node: Any, source: bytes) -> str:
    return _strict(source, node.start_byte, node.end_byte)


def _check_header(node: Any, source: bytes) -> None:
    """A malformed name can surface as a stray ERROR node; validate bytes up to the body."""
    body = node.child_by_field_name("body")
    _strict(source, node.start_byte, body.start_byte if body is not None else node.end_byte)


def _is_anchor(node: Any) -> bool:
    t = node.type
    return t not in _NOT_ANCHORS and t.endswith(("_statement", "_declaration", "_definition"))


def _has_error_ancestor(node: Any) -> bool:
    cur = node
    while cur is not None:
        if cur.type == "ERROR":
            return True
        cur = cur.parent
    return False


def _namespace_ranges(root: Any, source: bytes) -> list[tuple[int, int, str]]:
    ranges: list[tuple[int, int, str]] = []
    open_end = len(source) + 1
    for child in root.children:
        if child.type != "namespace_definition":
            continue
        name = child.child_by_field_name("name")
        text = _ident(name, source) if name is not None else ""
        if child.child_by_field_name("body") is not None:
            ranges.append((child.start_byte, child.end_byte, text))
        else:
            if ranges and ranges[-1][1] == open_end:  # close previous unbraced namespace
                ranges[-1] = (ranges[-1][0], child.start_byte, ranges[-1][2])
            ranges.append((child.start_byte, open_end, text))
    return ranges


def _namespace_at(ranges: list[tuple[int, int, str]], pos: int) -> str:
    found = ""
    for start, end, name in ranges:
        if start <= pos < end:
            found = name
    return found


def _anonymous_name(node: Any) -> str:
    """`class@anonymous#<k>`: the k-th anonymous class in file order (PHP's own name embeds a byte offset)."""
    root = node
    while root.parent is not None:
        root = root.parent
    stack, k = [root], 0
    while stack:
        cur = stack.pop()
        if cur.type == _ANONYMOUS:
            k += 1
            if cur.start_byte == node.start_byte:
                break
        stack.extend(reversed(cur.children))
    return f"class@anonymous#{k}"


def symbol_path(node: Any, source: bytes, namespace: str) -> str:
    """`<ns>\\<Class>::<method>`, `<ns>\\<Class>`, `<ns>\\<function>` or `<file>` for the node's scope."""
    prefix = f"{namespace}\\" if namespace else ""
    cur = node
    while cur is not None:
        name = cur.child_by_field_name("name") if cur.type != "program" else None
        if name is not None and (cur.type in _CLASS_LIKE or cur.type in _CALLABLE):
            _check_header(cur, source)
        if cur.type == "method_declaration" and name is not None:
            owner = cur.parent
            while owner is not None and owner.type not in _CLASS_LIKE and owner.type != _ANONYMOUS:
                owner = owner.parent
            if owner is not None and owner.type == _ANONYMOUS:
                return f"{prefix}{_anonymous_name(owner)}::{_ident(name, source)}"
            if owner is not None:
                _check_header(owner, source)
            cls = owner.child_by_field_name("name") if owner is not None else None
            cname = _ident(cls, source) if cls is not None else ""
            return f"{prefix}{cname}::{_ident(name, source)}"
        if cur.type in _CLASS_LIKE and name is not None:
            return f"{prefix}{_ident(name, source)}"
        if cur.type == "function_definition" and name is not None:
            return f"{prefix}{_ident(name, source)}"
        cur = cur.parent
    return FILE_SYMBOL


def _walk(root: Any) -> tuple[list[Any], list[Any]]:
    comments: list[Any] = []
    anchors: list[Any] = []
    stack = [root]
    while stack:
        node = stack.pop()
        if node.type == "comment":
            comments.append(node)
            continue
        if _is_anchor(node):
            anchors.append(node)
        stack.extend(reversed(node.children))
    comments.sort(key=lambda n: n.start_byte)
    anchors.sort(key=lambda n: n.start_byte)
    return comments, anchors


def _has_code(segment: bytes, tags_are_code: bool) -> bool:
    if not tags_are_code:  # PHPCS skips T_OPEN_TAG / T_CLOSE_TAG when looking for row content (G4)
        segment = _PHP_TAGS.sub(b"", segment)
    return bool(segment.strip())


def _is_trailing(comment: Any, source: bytes, tags_are_code: bool = True) -> bool:
    """Trailing only if code (not just other comments) precedes the comment on its row."""
    line_start = source.rfind(b"\n", 0, comment.start_byte) + 1
    end, prev = comment.start_byte, comment.prev_sibling
    while prev is not None and prev.type == "comment" and prev.end_byte > line_start:
        end, prev = prev.start_byte, prev.prev_sibling
    return _has_code(source[line_start:end], tags_are_code)


def _code_after(comment: Any, source: bytes, tags_are_code: bool = True) -> bool:
    """Code (not just other comments) follows the comment on its end row."""
    line_end = source.find(b"\n", comment.end_byte)
    line_end = len(source) if line_end < 0 else line_end
    pos, nxt = comment.end_byte, comment.next_sibling
    while nxt is not None and nxt.type == "comment" and nxt.start_byte < line_end:
        if _has_code(source[pos : nxt.start_byte], tags_are_code):
            return True
        pos, nxt = nxt.end_byte, nxt.next_sibling
    return pos < line_end and _has_code(source[pos:line_end], tags_are_code)


def _ignored_row(raw: _Raw, source: bytes) -> tuple[int, bool]:
    """(row a directive ignores, whether code shares that row with its comment); spec R4 "Anchor hash", probes D9.

    PHPCS reads a block comment row by row, so the directive's own row decides. PHPStan reads the comment as one
    token: `-line` covers its end row, an identifier ignore its start row (trailing) or end row (code follows).
    """
    comment = raw.comment
    start, end, row = comment.start_point.row, comment.end_point.row, raw.line
    if raw.row_rule == "next":
        return end + 1, False
    tags_are_code = raw.tool != "phpcs"  # PHPStan counts `<?php` / `?>` as code on the row, PHPCS does not
    before = _is_trailing(comment, source, tags_are_code)
    after = raw.tool in _LINE_SCOPED and _code_after(comment, source, tags_are_code)
    if raw.tool == "phpcs":
        if (row == start and before) or (row == end and after):
            return row, True
        return row + 1, row + 1 == end and after
    if raw.row_rule == "end":
        return end, after or (start == end and before)
    if before:
        return start, True
    if after:
        return end, True
    return end + 1, False


def _anchor_for(raw: _Raw, source: bytes, anchors: list[Any]) -> Any | None:
    if _has_error_ancestor(raw.comment):
        return None
    row, shared = _ignored_row(raw, source)
    if shared:
        best = None
        for node in anchors:
            if node.start_point.row <= row <= node.end_point.row and (
                best is None or node.start_byte >= best.start_byte
            ):
                best = node
        return best
    sib = raw.comment.next_named_sibling
    while sib is not None:
        if _is_anchor(sib):
            return sib
        sib = sib.next_named_sibling
    return None


def _body_derived(tool: str, codes: tuple[str, ...]) -> bool:
    """Codes that may cover body-derived errors keep the whole-node hash (spec R4)."""
    if not codes:
        return True
    for code in codes:
        parts = code.split(".")
        if tool == "phpcs" and len(parts) < 3:  # whole standard or category
            return True
        if any(word in part.lower() for part in parts for word in _METRIC_WORDS):
            return True
    return False


def _anchor_hash(raw: _Raw, anchor: Any, root: Any, source: bytes) -> tuple[str, bool]:
    """(hash, row-scoped): line-scoped tools fingerprint the ignored line or declaration header (spec R4 "Anchor hash").

    The declaration hash applies only when the ignored row is the declaration's start row; an ignore above a blank or
    docblock row suppresses nothing on the declaration (4.3.1 F2).
    """
    if raw.tool not in _LINE_SCOPED:
        return norm_hash(anchor, source), False  # psalm: the declaration/statement is its scope
    row = _ignored_row(raw, source)[0]  # the row `_anchor_for` reads
    if (anchor.type in _CLASS_LIKE or anchor.type in _CALLABLE) and row == anchor.start_point.row:
        if _body_derived(raw.tool, raw.codes):
            return norm_hash(anchor, source), False  # body-derived metrics
        return header_hash(anchor, source), False
    return line_hash(root, source, row), True


def _scan_comments(comments: list[Any], source: bytes) -> list[_Raw]:
    raws: list[_Raw] = []
    for comment in comments:
        text = source[comment.start_byte : comment.end_byte].decode("utf-8", errors="replace")
        for offset, line in comment_lines(text):
            for form, tool, codes, rule in scan_line(line):
                raws.append(_Raw(form, tool, codes, comment, comment.start_point.row + offset, rule))
    return raws


def collect(
    parsed: ParsedPhp,
) -> tuple[list[PointSuppression], list[WindowSuppression], list[FileSuppression]]:
    source = parsed.source
    root = parsed.tree.root_node
    ns_ranges = _namespace_ranges(root, source)
    comments, anchors = _walk(root)
    points: list[PointSuppression] = []
    files: list[FileSuppression] = []
    open_windows: list[dict[str, Any]] = []
    done: list[dict[str, Any]] = []

    def scope(node: Any) -> str:
        return symbol_path(node, source, _namespace_at(ns_ranges, node.start_byte))

    for raw in _scan_comments(comments, source):
        row = raw.line
        line_no = row + 1
        if raw.form in ("point", "unknown"):
            anchor = _anchor_for(raw, source, anchors)
            tool = raw.tool
            known = anchor is not None and tool != "phpcs-unknown"
            digest, row_scoped = _anchor_hash(raw, anchor, root, source) if known else (None, False)
            points.append(
                PointSuppression(
                    symbol=scope(anchor if anchor is not None else raw.comment),
                    tool=tool,
                    codes=raw.codes,
                    anchor_kind=anchor.type if known else None,
                    anchor_hash=digest,
                    line=line_no,
                    row_scoped=row_scoped,
                )
            )
        elif raw.form == "file":
            files.append(FileSuppression(raw.tool, raw.codes, line_no))
        elif raw.form == "disable":
            open_windows.append(
                {
                    "symbol": scope(raw.comment),
                    "codes": raw.codes,
                    "start": row,  # PHPCS suppresses whole rows from the disable row on (I2)
                    "end": None,
                    "line": line_no,
                }
            )
        elif raw.form == "enable":
            keep = []
            for win in open_windows:
                covered = within(win["codes"], raw.codes, hierarchical=True)  # a narrower enable keeps it open
                if covered:
                    win["end"] = row  # the enable row itself is not suppressed (probed)
                    done.append(win)
                else:
                    keep.append(win)
            open_windows = keep
    for comment in comments:  # PHPMD: kind + name anchor, the annotation covers the whole declaration (R4)
        decl = None if _has_error_ancestor(comment) else phpmd.declaration_after(comment, source)
        for codes, row in phpmd.annotations(comment, source):
            kind, digest = (None, None) if decl is None else (decl.type, declaration_name_hash(decl, source))
            header = None if decl is None else header_hash(decl, source)
            points.append(
                PointSuppression(scope(comment if decl is None else decl), "phpmd", codes, kind, digest, row + 1, header)
            )
    windows = [_window(w, anchors, source, closed=True) for w in done]
    windows += [_window(w, anchors, source, closed=False) for w in open_windows]
    windows.sort(key=lambda w: (w.line, w.symbol, w.codes))
    return points, windows, files


def _window(win: dict[str, Any], anchors: list[Any], source: bytes, closed: bool) -> WindowSuppression:
    """Covered: whole rows [disable row, enable row), or up to EOF, and every anchor whose row span meets them (R3, I2)."""
    start, end = win["start"], win["end"] if closed else source.count(b"\n") + 1
    hashes = sorted(norm_hash(n, source) for n in anchors if n.start_point.row < end and n.end_point.row >= start)
    return WindowSuppression(
        symbol=win["symbol"],
        codes=win["codes"],
        closed=closed,
        statements=tuple(hashes),
        line=win["line"],
        rows=(start, end),
    )


def namespace_resolver(root: Any, source: bytes) -> Callable[[int], str]:
    """Return `pos -> namespace` for a parsed file (handles braced and unbraced namespaces)."""
    ranges = _namespace_ranges(root, source)
    return lambda pos: _namespace_at(ranges, pos)
