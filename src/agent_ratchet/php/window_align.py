"""phpcs window growth by token alignment (spec R6, I2).

TARGET leaf tokens (comments and inline HTML tags and words included, whitespace ignored) are aligned to BASE tokens by their
(type, text) sequence. Window bounds are not code and are left out, so a moved bound never displaces the alignment
of the code it moved over: phpcs directive comments, and the `<?php` / `?>` pair that encloses one alone. Every
token row on a covered TARGET row that aligns to a BASE token must have been covered in BASE by windows with an
equal or broader code set; unaligned tokens are inserted code. Nothing offsets growth: PHPCS suppresses every
covered row, so rows a window releases elsewhere do not count. Multi-row tokens (strings, heredocs) are checked
row by row, relative to the token's first row.
"""

from __future__ import annotations

import re
from bisect import bisect_left, bisect_right
from collections.abc import Sequence
from difflib import SequenceMatcher

Token = tuple[str, bytes, int, int]  # type, text, first row, last row
Span = tuple[int, tuple[str, ...], int, int]  # disable line, codes, first covered row, end row (exclusive)
_ALL = None  # a window without codes covers every code
# a comment line that starts (after ` \t/*#` and an optional `@`) with a phpcs keyword (R4 G2, G6)
_BOUND = re.compile(rb"^[ \t/*#]*@?(?:phpcs:|codingStandardsIgnore)", re.IGNORECASE | re.MULTILINE)


def _is_bound(tok: Token) -> bool:
    return tok[0] == "comment" and _BOUND.search(tok[1]) is not None


def alignable(tokens: Sequence[Token]) -> tuple[Token, ...]:
    """Tokens that take part in the alignment: everything except window bounds, i.e. phpcs directive comments and
    the `<?php` / `?>` pair around a bound comment that stands alone between them."""
    drop: set[int] = set()
    for k, tok in enumerate(tokens):
        if _is_bound(tok):
            drop.add(k)
            if 0 < k < len(tokens) - 1 and tokens[k - 1][0] == "php_tag" and tokens[k + 1][0] == "php_end_tag":
                drop |= {k - 1, k + 1}
    return tuple(t for k, t in enumerate(tokens) if k not in drop)


def _offsets(tok: Token, start: int, end: int) -> range:
    return range(max(tok[2], start) - tok[2], min(tok[3], end - 1) - tok[2] + 1)


def _in_rows(tokens: Sequence[Token], start: int, end: int) -> range:
    """Indexes of tokens meeting rows [start, end): first and last rows are both non-decreasing in source order."""
    lo = bisect_left([t[3] for t in tokens], start)
    hi = bisect_right([t[2] for t in tokens], end - 1)
    return range(lo, max(lo, hi))


def _cover(tokens: Sequence[Token], spans: Sequence[Span]) -> dict[tuple[int, int], frozenset[str] | None]:
    """(token index, row offset) -> union of the codes of every window covering it (`None`: all codes)."""
    cover: dict[tuple[int, int], frozenset[str] | None] = {}
    for _, codes, start, end in spans:
        for i in _in_rows(tokens, start, end):
            for off in _offsets(tokens[i], start, end):
                had = cover.get((i, off), frozenset())
                cover[(i, off)] = _ALL if had is _ALL or not codes else had | frozenset(codes)
    return cover


def _within(codes: tuple[str, ...], had: frozenset[str] | None) -> bool:
    if had is _ALL:
        return True
    return bool(codes) and all(any(c == h or c.startswith(h + ".") for h in had) for c in codes)


def _align(base: Sequence[Token], target: Sequence[Token]) -> dict[int, int]:
    """TARGET index -> BASE index for tokens matched by (type, text). Identical leading and trailing rows are matched
    directly (whole rows, so an inserted row never borrows tokens of the row after it); the rest via SequenceMatcher."""
    a, b = [t[:2] for t in base], [t[:2] for t in target]
    head = tail = 0
    for x, y in zip(_row_groups(base), _row_groups(target)):
        if a[head : head + x] != b[head : head + y] or x != y:
            break
        head += x
    for x, y in zip(reversed(_row_groups(base)), reversed(_row_groups(target))):
        if x != y or head + tail + x > min(len(a), len(b)) or a[len(a) - tail - x : len(a) - tail] != b[
            len(b) - tail - y : len(b) - tail
        ]:
            break
        tail += x
    pairs = {j: j for j in range(head)}
    pairs.update({len(b) - 1 - k: len(a) - 1 - k for k in range(tail)})
    mid = SequenceMatcher(None, a[head : len(a) - tail], b[head : len(b) - tail], autojunk=False)
    for i, j, n in mid.get_matching_blocks():
        pairs.update({head + j + k: head + i + k for k in range(n)})
    return pairs


def _row_groups(tokens: Sequence[Token]) -> list[int]:
    """Token counts of consecutive runs that start on the same row."""
    sizes: list[int] = []
    last = None
    for tok in tokens:
        if tok[2] != last:
            sizes.append(0)
            last = tok[2]
        sizes[-1] += 1
    return sizes


def grown_windows(
    base: Sequence[Token], base_spans: Sequence[Span], target: Sequence[Token], target_spans: Sequence[Span]
) -> set[tuple[int, tuple[str, ...]]]:
    """(line, codes) of every TARGET window covering an existing token row that no BASE window with an equal or
    broader code set covered."""
    if not target_spans:
        return set()
    bcover, aligned = _cover(base, base_spans), _align(base, target)
    return {
        (line, codes)
        for line, codes, start, end in target_spans
        if any(
            not _within(codes, bcover.get((i, off), frozenset()))
            for j in _in_rows(target, start, end)
            if (i := aligned.get(j)) is not None
            for off in _offsets(target[j], start, end)
        )
    }
