"""BASE/TARGET comparison of PHP facts: suppression and test tampering, parse degradation (spec R6)."""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from agent_ratchet.facts.model import CanonicalFact
from agent_ratchet.git_guard_io import SlopViolation
from agent_ratchet.php.directives import FILE_SYMBOL
from agent_ratchet.php.extract import FILE, GAP, POINT, TEST, WINDOW, Analysis, analyze
from agent_ratchet.transitions import FactState, evaluate

ADDED, REBOUND = "php_suppression_added", "php_suppression_rebound"
UNKNOWN_ANCHOR, EXPANDED = "php_suppression_anchor_unknown", "php_suppression_range_expanded"
REMOVED, WEAKENED, DEGRADED = "php_test_removed", "php_test_weakened", "php_parse_degraded"
_SILENCEABLE = frozenset({ADDED, REBOUND, EXPANDED})
_EMPTY = Analysis((), {})


def _codes(f: CanonicalFact) -> tuple[str, ...]:
    return tuple(f.identity["codes"])


def _anchor(f: CanonicalFact) -> tuple[Any, Any]:
    return (f.payload["anchor_ast_kind"], f.payload["anchor_norm_hash"])


def _narrower(inner: tuple[str, ...], outer: tuple[str, ...]) -> bool:
    """`inner` suppresses strictly less than `outer` (an empty code list means every code)."""
    return inner != outer and bool(inner) and (not outer or set(inner) < set(outer))


def _symbol(f: CanonicalFact) -> str:
    if f.kind == TEST:
        return f"{f.identity['class_fqn']}::{f.identity['method']}"
    return f.identity.get("symbol", FILE_SYMBOL)


def _under(symbol: str, dead: set[str]) -> bool:
    return symbol in dead or any(d != FILE_SYMBOL and symbol.startswith(d + "::") for d in dead)


def _pair(
    base: list[CanonicalFact], target: list[CanonicalFact], ok: Callable[[CanonicalFact, CanonicalFact], bool]
) -> list[tuple[CanonicalFact, CanonicalFact]]:
    """Greedily pair target facts with base facts (source order), consuming both lists."""
    pairs: list[tuple[CanonicalFact, CanonicalFact]] = []
    for t in list(target):
        idx = next((i for i, b in enumerate(base) if ok(t, b)), None)
        if idx is not None:
            target.remove(t)
            pairs.append((t, base.pop(idx)))
    return pairs


class _Findings:
    """Findings keyed by (category, identity); a repeated identity collapses into one with a count."""

    def __init__(self, path: str, exceptions: Sequence[Mapping[str, Any]]) -> None:
        self.path = path
        self.trusted = {(e["path"], e["symbol"], e["tool"], tuple(sorted(e["codes"]))) for e in exceptions}
        self.items: dict[tuple[str, str, str, tuple[str, ...]], list[int]] = {}

    def add(self, category: str, f: CanonicalFact) -> None:
        tool = f.identity.get("tool", "")
        key = (category, _symbol(f), tool, _codes(f))
        if category in _SILENCEABLE and (self.path, *key[1:]) in self.trusted:
            return
        entry = self.items.setdefault(key, [0, 1])
        entry[0] += 1
        entry[1] = max(entry[1], f.origin.line or 1)

    def violations(self) -> list[SlopViolation]:
        out = []
        for (category, symbol, tool, codes), (count, line) in self.items.items():
            label = f"{tool} [{', '.join(codes) or 'all'}] in {symbol}" + (f" (x{count})" if count > 1 else "")
            out.append(SlopViolation(self.path, line, category, f"{_MESSAGES[category]}: {label}", f"{tool} {','.join(codes)}".strip()))
        return out


_MESSAGES = {
    ADDED: "PHP suppression added",
    REBOUND: "PHP suppression re-pointed to another statement",
    UNKNOWN_ANCHOR: "PHP suppression with unresolved anchor",
    EXPANDED: "PHP suppression range expanded",
}


def _points(base: list[CanonicalFact], target: list[CanonicalFact], out: _Findings) -> None:
    groups: dict[tuple[str, str], tuple[list[CanonicalFact], list[CanonicalFact]]] = {}
    for side, facts in ((0, base), (1, target)):
        for f in facts:
            groups.setdefault((f.identity["symbol"], f.identity["tool"]), ([], []))[side].append(f)
    for b, t in groups.values():
        _pair(b, t, lambda x, y: _codes(x) == _codes(y) and _anchor(x) == _anchor(y))
        flagged: list[CanonicalFact] = []
        for x, _ in _pair(b, t, lambda x, y: _codes(x) == _codes(y)):
            out.add(REBOUND, x)
            flagged.append(x)
        _pair(b, t, lambda x, y: _narrower(_codes(x), _codes(y)) and _anchor(x) == _anchor(y))
        for x, _ in _pair(b, t, lambda x, y: _narrower(_codes(x), _codes(y))):
            out.add(REBOUND, x)
            flagged.append(x)
        for x in t:
            out.add(ADDED, x)
            flagged.append(x)
        for x in flagged:
            if x.payload["anchor_norm_hash"] is None and x.identity["tool"] != "phpcs-unknown":
                out.add(UNKNOWN_ANCHOR, x)


def _files(base: list[CanonicalFact], target: list[CanonicalFact], out: _Findings) -> None:
    for tool in {f.identity["tool"] for f in target}:
        b = [f for f in base if f.identity["tool"] == tool]
        t = [f for f in target if f.identity["tool"] == tool]
        _pair(b, t, lambda x, y: _codes(x) == _codes(y))
        _pair(b, t, lambda x, y: _narrower(_codes(x), _codes(y)))
        for x in t:
            out.add(ADDED, x)


def _grew(t: CanonicalFact, b: CanonicalFact) -> bool:
    gained = Counter(t.payload["statements"]) - Counter(b.payload["statements"])
    return bool(gained) or (b.payload["closed"] and not t.payload["closed"])


def _windows(base: list[CanonicalFact], target: list[CanonicalFact], out: _Findings) -> None:
    groups: dict[str, tuple[list[CanonicalFact], list[CanonicalFact]]] = {}
    for side, facts in ((0, base), (1, target)):
        for f in facts:
            groups.setdefault(f.identity["symbol"], ([], []))[side].append(f)
    for b, t in groups.values():
        _pair(b, t, lambda x, y: _codes(x) == _codes(y) and x.payload_hash == y.payload_hash)
        pairs = _pair(b, t, lambda x, y: _codes(x) == _codes(y))
        pairs += _pair(b, t, lambda x, y: _narrower(_codes(x), _codes(y)))
        for x, y in pairs:
            if _grew(x, y):
                out.add(EXPANDED, x)
        for x in t:
            out.add(EXPANDED, x)


def _weakness(b: CanonicalFact, t: CanonicalFact) -> list[str]:
    bp, tp = b.payload, t.payload
    why = [f"{k} {bp[k]} -> {tp[k]}" for k in ("assertions", "expects") if tp[k] < bp[k]]
    why += [f"{k} {bp[k]} -> {tp[k]}" for k in ("skips", "incompletes") if tp[k] > bp[k]]
    lost = Counter(bp["expect_exception"]) - Counter(tp["expect_exception"])
    why += [f"{name} dropped" for name in sorted(lost)]
    why += [f"data provider {name} dropped" for name in sorted(set(bp["data_providers"]) - set(tp["data_providers"]))]
    return why


def _unmatched_removed(removed: list[CanonicalFact], added: list[CanonicalFact]) -> list[CanonicalFact]:
    """Removed tests with no added test of the same payload (a pure rename or move keeps the payload)."""
    pool = Counter(f.payload_hash for f in added)
    left = []
    for f in removed:
        if pool[f.payload_hash] > 0:
            pool[f.payload_hash] -= 1
        else:
            left.append(f)
    return left


def _removed_violation(f: CanonicalFact) -> SlopViolation:
    name = _symbol(f)
    return SlopViolation(f.origin.path, f.origin.line or 1, REMOVED, f"PHPUnit test removed: {name}", name)


def _test_key(f: CanonicalFact) -> tuple[str, str]:
    return (f.identity["class_fqn"], f.identity["method"])


def php_test_delta(base: list[CanonicalFact], target: list[CanonicalFact]) -> tuple[list[CanonicalFact], list[CanonicalFact]]:
    """Tests present only in BASE and only in TARGET (identity compared without the path, so moves line up)."""
    bk, tk = {_test_key(f) for f in base}, {_test_key(f) for f in target}
    return [f for f in base if _test_key(f) not in tk], [f for f in target if _test_key(f) not in bk]


def _tests(base: list[CanonicalFact], target: list[CanonicalFact], path: str) -> list[SlopViolation]:
    by_key = {_test_key(f): f for f in base}
    res: list[SlopViolation] = []
    for t in target:
        b = by_key.get(_test_key(t))
        why = _weakness(b, t) if b is not None else []
        if why:
            name = _symbol(t)
            res.append(SlopViolation(path, t.origin.line or 1, WEAKENED, f"PHPUnit test weakened: {name} ({'; '.join(why)})", name))
    removed, added = php_test_delta(base, target)
    return res + [_removed_violation(f) for f in _unmatched_removed(removed, added)]


def compare_php_tests_across(removed: list[CanonicalFact], added: list[CanonicalFact]) -> list[SlopViolation]:
    """Cross-file rename/move matching: removed `php.test` facts nobody re-added (same payload) are violations."""
    return sorted((_removed_violation(f) for f in _unmatched_removed(removed, added)), key=lambda v: (v.file, v.line, v.message))


def _degraded(b: Analysis, t: Analysis, path: str) -> tuple[list[SlopViolation], set[str]]:
    lines = {f.identity["symbol"]: f.origin.line or 1 for f in reversed(t.facts) if f.kind == GAP}
    out: list[SlopViolation] = []
    dead: set[str] = set()
    for symbol, digest in sorted(t.gap_hashes.items()):
        gap = FactState("unknown", symbol, digest, loss_reason="syntax_error")
        # An unchanged symbol that already had the gap is unknown -> unknown; anything else was readable before.
        before = gap if b.gap_hashes.get(symbol) == digest else FactState("pass", symbol, "readable-or-different")
        if evaluate(before, gap, ctx_delta=False).code == "degraded_epistemic":
            out.append(SlopViolation(path, lines.get(symbol, 1), DEGRADED, f"PHP parse gap in changed code: {symbol}", symbol))
            dead.add(symbol)
    return out, dead


def _decode_violation(path: str, side: str) -> SlopViolation:
    msg = f"PHP file is not analyzable ({side} contains non-UTF-8 identifiers)"
    return SlopViolation(path, 1, DEGRADED, msg, side)


def _live(an: Analysis, kind: str, dead: set[str]) -> list[CanonicalFact]:
    return [f for f in an.facts if f.kind == kind and not _under(_symbol(f), dead)]


def _sorted(items: list[SlopViolation]) -> list[SlopViolation]:
    return sorted(items, key=lambda v: (v.file, v.line, v.category, v.message))


def compare_php_entry(
    base: bytes | None,
    target: bytes | None,
    base_path: str | None,
    target_path: str,
    exceptions: Sequence[Mapping[str, Any]],
) -> list[SlopViolation]:
    """Findings for one paired entry. `exceptions` must already be restricted to those trusted at BASE."""
    if base is not None and base == target:
        return []
    old_path = base_path or target_path
    b = analyze(base, old_path) if base is not None else _EMPTY
    if target is None:
        if b.decode_error:
            return [_decode_violation(old_path, "BASE")]
        return _sorted([_removed_violation(f) for f in b.facts if f.kind == TEST])
    t = analyze(target, target_path)
    if t.decode_error or b.decode_error:
        return [_decode_violation(target_path, "TARGET" if t.decode_error else "BASE")]
    degraded, dead = _degraded(b, t, target_path)  # only symbols that already block are skipped below
    out = _Findings(target_path, exceptions)

    def pick(kind: str) -> tuple[list[CanonicalFact], list[CanonicalFact]]:
        return _live(b, kind, dead), _live(t, kind, dead)

    _points(*pick(POINT), out)
    _windows(*pick(WINDOW), out)
    _files(*pick(FILE), out)
    found = out.violations() + degraded
    return _sorted(found + _tests(*pick(TEST), target_path))
