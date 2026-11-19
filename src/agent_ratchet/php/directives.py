"""PHP suppression directives (phpstan, phpcs, psalm) with anchors and windows (spec R3/R4)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from agent_ratchet.php.parser import ParsedPhp, norm_hash

FILE_SYMBOL = "<file>"
_CLASS_LIKE = {"class_declaration", "interface_declaration", "trait_declaration", "enum_declaration"}
_CALLABLE = {"method_declaration", "function_definition"}
_NOT_ANCHORS = {"compound_statement", "namespace_definition"}
_DIRECTIVE = re.compile(
    r"(?P<stan>@phpstan-ignore(?P<suffix>-next-line|-line)?(?![\w-]))"
    r"|phpcs:(?P<cs>[a-z]+)"
    r"|@codingStandardsIgnore(?P<legacy>Line|Start|End|File)\b"
    r"|(?P<psalm>@psalm-suppress\b)",
    re.IGNORECASE,
)
_PHPCS_FORMS = {"ignore": "point", "disable": "disable", "enable": "enable", "ignorefile": "file"}
_LEGACY_FORMS = {"line": "point", "start": "disable", "end": "enable", "file": "file"}
_PAREN = re.compile(r"\([^)]*\)")


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


@dataclass(frozen=True)
class WindowSuppression:
    symbol: str
    codes: tuple[str, ...]
    closed: bool
    statements: tuple[str, ...]
    line: int


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
    next_line: bool = False


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
            while owner is not None and owner.type not in _CLASS_LIKE:
                owner = owner.parent
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


def _split_codes(text: str) -> tuple[str, ...]:
    text = text.split("--", 1)[0]
    text = _PAREN.sub(" ", text)
    return tuple(sorted({c for c in re.split(r"[,\s]+", text) if c}))


def _comment_lines(text: str) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    for i, line in enumerate(text.split("\n")):
        line = line.strip()
        line = line.removeprefix("/**").removeprefix("/*").removeprefix("//").removeprefix("#")
        line = line.removesuffix("*/").lstrip("*").strip()
        out.append((i, line))
    return out


def _scan_line(line: str) -> list[tuple[str, str, tuple[str, ...], bool]]:
    """Return (form, tool, codes, next_line) for every directive on a line, in order."""
    matches = list(_DIRECTIVE.finditer(line))
    out: list[tuple[str, str, tuple[str, ...], bool]] = []
    for i, m in enumerate(matches):
        end = matches[i + 1].start() if i + 1 < len(matches) else len(line)
        rest = line[m.end() : end]
        if m.group("stan") is not None:
            suffix = (m.group("suffix") or "").lower()
            codes = () if suffix else _split_codes(rest)
            out.append(("point", "phpstan", codes, suffix == "-next-line"))
        elif m.group("cs") is not None:
            form = _PHPCS_FORMS.get(m.group("cs").lower())
            if form is None:
                out.append(("unknown", "phpcs-unknown", _split_codes(rest), False))
            else:
                out.append((form, "phpcs", _split_codes(rest), False))
        elif m.group("legacy") is not None:
            form = _LEGACY_FORMS[m.group("legacy").lower()]
            out.append((form, "phpcs", (), False))
        else:
            out.append(("point", "psalm", _split_codes(rest), False))
    return out


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


def _is_trailing(comment: Any, source: bytes) -> bool:
    line_start = source.rfind(b"\n", 0, comment.start_byte) + 1
    return bool(source[line_start : comment.start_byte].strip())


def _anchor_for(
    comment: Any, line_row: int, source: bytes, anchors: list[Any], next_line: bool = False
) -> Any | None:
    if _has_error_ancestor(comment):
        return None
    if _is_trailing(comment, source) and not next_line:
        best = None
        for node in anchors:
            if node.start_point.row <= line_row <= node.end_point.row and (
                best is None or node.start_byte >= best.start_byte
            ):
                best = node
        return best
    sib = comment.next_named_sibling
    while sib is not None:
        if _is_anchor(sib):
            return sib
        sib = sib.next_named_sibling
    return None


def _scan_comments(comments: list[Any], source: bytes) -> list[_Raw]:
    raws: list[_Raw] = []
    for comment in comments:
        text = source[comment.start_byte : comment.end_byte].decode("utf-8", errors="replace")
        for offset, line in _comment_lines(text):
            for form, tool, codes, nxt in _scan_line(line):
                raws.append(_Raw(form, tool, codes, comment, comment.start_point.row + offset, nxt))
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
            anchor = _anchor_for(raw.comment, row, source, anchors, raw.next_line)
            tool = raw.tool
            points.append(
                PointSuppression(
                    symbol=scope(anchor if anchor is not None else raw.comment),
                    tool=tool,
                    codes=raw.codes,
                    anchor_kind=None if anchor is None or tool == "phpcs-unknown" else anchor.type,
                    anchor_hash=None
                    if anchor is None or tool == "phpcs-unknown"
                    else norm_hash(anchor, source),
                    line=line_no,
                )
            )
        elif raw.form == "file":
            files.append(FileSuppression(raw.tool, raw.codes, line_no))
        elif raw.form == "disable":
            open_windows.append(
                {
                    "symbol": scope(raw.comment),
                    "codes": raw.codes,
                    "start": raw.comment.end_byte,
                    "end": None,
                    "line": line_no,
                }
            )
        elif raw.form == "enable":
            keep = []
            for win in open_windows:
                covered = not raw.codes or (win["codes"] and set(win["codes"]) <= set(raw.codes))
                if covered:
                    win["end"] = raw.comment.start_byte
                    done.append(win)
                else:
                    keep.append(win)
            open_windows = keep
    windows = [_window(w, anchors, source, closed=True) for w in done]
    windows += [_window(w, anchors, source, closed=False) for w in open_windows]
    windows.sort(key=lambda w: (w.line, w.symbol, w.codes))
    return points, windows, files


def _window(win: dict[str, Any], anchors: list[Any], source: bytes, closed: bool) -> WindowSuppression:
    end = win["end"] if closed else len(source)
    hashes = sorted(norm_hash(n, source) for n in anchors if win["start"] <= n.start_byte < end)
    return WindowSuppression(
        symbol=win["symbol"],
        codes=win["codes"],
        closed=closed,
        statements=tuple(hashes),
        line=win["line"],
    )
