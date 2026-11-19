"""phpcs window growth by token alignment (spec R6, I2).

TARGET leaf tokens (comments and inline HTML tags and words included, whitespace ignored) are aligned to BASE tokens by their
(type, text) sequence. Window bounds are not code and are left out, so a moved bound never displaces the alignment
of the code it moved over: phpcs directive comments, and the `<?php` / `?>` pair that encloses one alone (checked
against the tags of the BASE bound with the same parse instead). Every token row on a covered TARGET row that aligns
to a BASE token must have been covered in BASE by windows with an equal or broader code set; unaligned tokens are
inserted code. Nothing offsets growth: PHPCS suppresses every covered row, so rows a window releases elsewhere do
not count. Multi-row tokens (strings, heredocs) are checked
row by row, relative to the token's first row.
"""

from __future__ import annotations

import re
from bisect import bisect_left, bisect_right
from collections.abc import Sequence
from difflib import SequenceMatcher

from agent_ratchet.php.directive_text import comment_lines, scan_line

Token = tuple[str, bytes, int, int]  # type, text, first row, last row
Span = tuple[int, tuple[str, ...], int, int]  # disable line, codes, first covered row, end row (exclusive)
_ALL = None  # a window without codes covers every code
# a comment line that starts (after ` \t/*#` and an optional `@`) with a phpcs keyword (R4 G2, G6)
_BOUND = re.compile(rb"^[ \t/*#]*@?(?:phpcs:|codingStandardsIgnore)", re.IGNORECASE | re.MULTILINE)


def _is_bound(tok: Token) -> bool:
    return tok[0] == "comment" and _BOUND.search(tok[1]) is not None


Tag = tuple[Token, bool] | None  # the tag next to a bound, and whether it was left out of the alignment
Unit = tuple[object, int, Tag, Tag]  # parsed bound, its first row, the `<?php` before it, the `?>` after it


def _key(text: bytes) -> object:
    """A bound as PHPCS reads it (kind and codes; no ` --` reason or spacing), so rewording it keeps its pair."""
    lines = comment_lines(text.decode("utf-8", errors="replace"))
    parsed = tuple((form, tool, codes) for _, line in lines for form, tool, codes, _ in scan_line(line))
    return parsed or text


def _split(tokens: Sequence[Token]) -> tuple[list[Token], list[Unit]]:
    """Tokens that take part in the alignment, and the window bounds left out of it: phpcs directive comments and
    the `<?php` / `?>` pair around a bound comment that stands alone between them."""
    kept: list[Token] = []
    units: list[Unit] = []
    tags: set[int] = set()
    for k, tok in enumerate(tokens):
        if _is_bound(tok):
            pre = tokens[k - 1] if k > 0 and tokens[k - 1][0] == "php_tag" else None
            post = tokens[k + 1] if k < len(tokens) - 1 and tokens[k + 1][0] == "php_end_tag" else None
            alone = pre is not None and post is not None
            if alone:
                tags |= {k - 1, k + 1}
                if kept and kept[-1] is pre:
                    kept.pop()
            tag_pre = None if pre is None else (pre, alone)
            units.append((_key(tok[1]), tok[2], tag_pre, None if post is None else (post, alone)))
        elif k not in tags:
            kept.append(tok)
    return kept, units


def _grown_tags(
    base: list[Unit], base_spans: Sequence[Span], target: list[Unit], target_spans: Sequence[Span]
) -> set[tuple[int, tuple[str, ...]]]:
    """(line, codes) of TARGET windows covering a bound's tag that BASE did not cover, where either side left the tag
    out of the alignment. Units pair by parsed bound; a tag on its own bound's row on both sides is judged with the
    bound, not as code (PHPCS ignores such rows)."""
    match = SequenceMatcher(None, [u[0] for u in base], [u[0] for u in target], autojunk=False)
    out: set[tuple[int, tuple[str, ...]]] = set()
    for i, j, n in match.get_matching_blocks():
        for (_, brow, *btags), (_, trow, *ttags) in zip(base[i : i + n], target[j : j + n], strict=True):
            for b, t in zip(btags, ttags, strict=True):
                if b is None or t is None or not (b[1] or t[1]) or (b[0][2] == brow and t[0][2] == trow):
                    continue
                had = _cover([b[0]], base_spans).get((0, 0), frozenset())
                row = t[0][2]
                out |= {(line, codes) for line, codes, s, e in target_spans if s <= row < e and not _within(codes, had)}
    return out


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


def _coarse(tokens: Sequence[Token]) -> tuple[list[Token], list[int]]:
    """Tokens with every inline HTML tag (`<name`, attributes, `>` on one row) joined into one, and the first fine
    index of each."""
    out: list[Token] = []
    first: list[int] = []
    k = 0
    while k < len(tokens):
        tok, n = tokens[k], 1
        if tok[0] == "text" and tok[1].startswith(b"<") and tok[1] != b"<":
            while k + n < len(tokens) and tokens[k + n][0] == "text" and tokens[k + n][2] == tok[2]:
                n += 1
                if tokens[k + n - 1][1] == b">":
                    break
            tok = ("text", b" ".join(t[1] for t in tokens[k : k + n]), tok[2], tok[3])
        out.append(tok)
        first.append(k)
        k += n
    first.append(len(tokens))
    return out, first


def _align_html(base: Sequence[Token], target: Sequence[Token]) -> dict[int, int]:
    """`_align` with whole HTML tags as tokens, so a moved row never wins the match by its attribute count; where
    one side's unmatched tags face the other's, their parts are aligned again, so an edited attribute leaves the
    rest of its tag aligned."""
    (cb, fb), (ct, ft) = _coarse(base), _coarse(target)
    pairs: dict[int, int] = {}
    last = (-1, -1)
    for cj, ci in [*sorted(_align(cb, ct).items()), (len(ct), len(cb))]:
        if cj < len(ct):
            pairs.update({ft[cj] + k: fb[ci] + k for k in range(ft[cj + 1] - ft[cj])})
        (bi, bj), (ti, tj) = (fb[last[1] + 1], fb[ci]), (ft[last[0] + 1], ft[cj])
        if bi < bj and ti < tj:
            gap = SequenceMatcher(None, [t[:2] for t in base[bi:bj]], [t[:2] for t in target[ti:tj]], autojunk=False)
            for i, j, n in gap.get_matching_blocks():
                pairs.update({ti + j + k: bi + i + k for k in range(n)})
        last = (cj, ci)
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
    base_tokens: Sequence[Token], base_spans: Sequence[Span], target_tokens: Sequence[Token], target_spans: Sequence[Span]
) -> set[tuple[int, tuple[str, ...]]]:
    """(line, codes) of every TARGET window covering an existing token row that no BASE window with an equal or
    broader code set covered."""
    if not target_spans:
        return set()
    (base, bunits), (target, tunits) = _split(base_tokens), _split(target_tokens)
    bcover, aligned = _cover(base, base_spans), _align_html(base, target)
    return _grown_tags(bunits, base_spans, tunits, target_spans) | {
        (line, codes)
        for line, codes, start, end in target_spans
        if any(
            not _within(codes, bcover.get((i, off), frozenset()))
            for j in _in_rows(target, start, end)
            if (i := aligned.get(j)) is not None
            for off in _offsets(target[j], start, end)
        )
    }
