"""phpcs window growth by token alignment (spec R6, I2).

TARGET leaf tokens (comments included, whitespace ignored) are aligned to BASE tokens by their (type, text)
sequence. Comments that carry phpcs directives are window bounds, not code, and are left out so a moved bound
never displaces the alignment of the code it moved over. A token on a covered TARGET row that aligns to a BASE
token must have been on a row that BASE windows with an equal or broader code set covered; unaligned tokens are
inserted code and never count. Multi-row tokens (strings, heredocs) are checked row by row, relative to the
token's first row. Rows of existing code a window releases offset identical rows it takes in (a slide between
copies of a statement).
"""

from __future__ import annotations

import re
from bisect import bisect_left, bisect_right
from collections import Counter
from collections.abc import Callable, Sequence
from difflib import SequenceMatcher

Token = tuple[str, bytes, int, int]  # type, text, first row, last row
Span = tuple[int, tuple[str, ...], int, int]  # disable line, codes, first covered row, end row (exclusive)
_ALL = None  # a window without codes covers every code
_BOUND = re.compile(rb"phpcs:|@codingStandardsIgnore", re.IGNORECASE)


def alignable(tokens: Sequence[Token]) -> tuple[Token, ...]:
    """Tokens that take part in the alignment: everything except comments carrying a phpcs directive."""
    return tuple(t for t in tokens if not (t[0] == "comment" and _BOUND.search(t[1])))


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


def _newly(
    tokens: Sequence[Token], cells: list[tuple[int, int]]
) -> Counter[tuple[tuple[str, bytes, int], ...]]:
    """Multiset of rows, each row the (type, text, row offset) of its listed token cells in source order."""
    rows: dict[int, list[tuple[int, int]]] = {}
    for idx, off in cells:
        rows.setdefault(tokens[idx][2] + off, []).append((idx, off))
    return Counter(tuple((*tokens[i][:2], o) for i, o in sorted(r)) for r in rows.values())


def grown_windows(
    base_tokens: Callable[[], Sequence[Token]],
    base_spans: Sequence[Span],
    base_rows: Sequence[bytes],
    target_tokens: Callable[[], Sequence[Token]],
    target_spans: Sequence[Span],
    target_rows: Sequence[bytes],
) -> set[tuple[int, tuple[str, ...]]]:
    """(line, codes) of every TARGET window covering existing code that BASE did not cover for those codes.

    Rows of existing code that leave every TARGET window offset identical rows that enter one, so a window sliding
    from one copy of a statement to another is not an expansion. A TARGET window whose covered rows are byte-identical
    to those of a BASE window with the same codes is skipped before any tokenizing (pre-filter, cost guard).
    """
    seen = set(zip((s[1] for s in base_spans), base_rows, strict=True))
    todo = [s for s, rows in zip(target_spans, target_rows, strict=True) if (s[1], rows) not in seen]
    if not todo:
        return set()
    base, target = base_tokens(), target_tokens()
    bcover, tcover, aligned = _cover(base, base_spans), _cover(target, target_spans), _align(base, target)
    back = {i: j for j, i in aligned.items()}
    grown: set[tuple[int, tuple[str, ...]]] = set()
    for line, codes, start, end in todo:
        entered = [
            (j, off)
            for j in _in_rows(target, start, end)
            if (i := aligned.get(j)) is not None
            for off in _offsets(target[j], start, end)
            if not _within(codes, bcover.get((i, off), frozenset()))
        ]
        if not entered:
            continue
        left = [
            (i, off)
            for (i, off), had in bcover.items()
            if _within(codes, had) and (j := back.get(i)) is not None and (j, off) not in tcover
        ]
        if _newly(target, entered) - _newly(base, left):
            grown.add((line, codes))
    return grown
