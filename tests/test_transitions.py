"""Tests for the paired BASE/HEAD transition engine (dormant)."""

from __future__ import annotations

import ast
from itertools import product
from pathlib import Path
from typing import get_args

import pytest

from agent_ratchet.transitions import (
    TRANSITIONS,
    Decision,
    FactState,
    LossReason,
    Status,
    _matching_rules,
    evaluate,
)

STATUSES = get_args(Status)
LOSS_REASONS = get_args(LossReason)
MODES = ("tier1", "full_ci")


def _loss_options(status: str) -> tuple[str | None, ...]:
    return LOSS_REASONS if status == "unknown" else (None,)


def _states(status: str, hashes: tuple[str, ...]):
    for loss in _loss_options(status):
        for ident, payload in product(hashes, repeat=2):
            yield FactState(status, ident, payload, "c", loss)  # type: ignore[arg-type]


def _all_inputs():
    for base_status, head_status in product(STATUSES, STATUSES):
        for base in _states(base_status, ("a",)):
            for head in _states(head_status, ("a", "b")):
                for ctx_delta in (False, True):
                    yield base, head, ctx_delta


def _resolved(rule, mode, mandatory):
    flag = rule.tier1_blocking if mode == "tier1" else rule.full_ci_blocking
    return mandatory if flag == "mandatory" else flag


def test_table_is_exhaustive():
    seen = 0
    for base, head, ctx_delta in _all_inputs():
        matches = _matching_rules(base, head, ctx_delta)
        assert matches, (base, head, ctx_delta)
        for mode in MODES:
            for mandatory in (False, True):
                got = evaluate(base, head, ctx_delta, mode=mode, mandatory=mandatory)
                rule = matches[0]
                assert got == Decision(
                    rule.code,
                    _resolved(rule, mode, mandatory),
                    head.loss_reason or base.loss_reason,
                )
        seen += 1
    assert seen > 0


def test_every_rule_is_reachable():
    first_hit = set()
    for base, head, ctx_delta in _all_inputs():
        first_hit.add(id(_matching_rules(base, head, ctx_delta)[0]))
    dead = [i + 1 for i, r in enumerate(TRANSITIONS) if id(r) not in first_hit]
    assert dead == []


def _fs(status, loss=None, ident="a", payload=None):
    return FactState(status, ident, ident if payload is None else payload, "c", loss)


SPEC_CASES = [
    # row, base, head, ctx_delta, (code, tier1, full_ci_non_mandatory, full_ci_mandatory)
    (1, _fs("unknown", "tool_failure"), _fs("unknown", "tool_failure", "b"), False,
     ("needs_tier2_verification", False, True, True)),
    (2, _fs("unknown", "tool_failure"), _fs("unknown", "tool_failure"), True,
     ("context_mutated_unknown", False, True, True)),
    (3, _fs("unknown", "tool_failure"), _fs("unknown", "tool_failure"), False,
     ("unchanged_unknown", False, False, True)),
    (4, _fs("pass"), _fs("unknown", "syntax_error"), False,
     ("degraded_epistemic", True, True, True)),
    (5, _fs("pass"), _fs("unknown", "coverage_gap"), False,
     ("incomplete", False, False, True)),
    (6, _fs("violation"), _fs("unknown", "tool_failure"), False,
     ("unverifiable_violation", True, True, True)),
    (7, _fs("unknown", "tool_failure"), _fs("pass"), False, ("pass", False, False, False)),
    (8, _fs("pass"), _fs("absent"), False, ("removed", False, False, False)),
    (9, _fs("absent"), _fs("unknown", "tool_failure"), False,
     ("needs_tier2_verification", False, True, True)),
    (9, _fs("not_applicable"), _fs("unknown", "tool_failure"), False,
     ("needs_tier2_verification", False, True, True)),
    (10, _fs("violation"), _fs("violation"), False, ("unchanged_violation", False, False, False)),
    (11, _fs("pass"), _fs("violation"), False, ("violation", True, True, True)),
    (11, _fs("violation"), _fs("violation", payload="b"), False, ("violation", True, True, True)),
    (12, _fs("pass"), _fs("not_applicable"), False, ("not_applicable", False, False, False)),
    (13, _fs("absent"), _fs("absent"), False, ("not_applicable", False, False, False)),
]


@pytest.mark.parametrize("row,base,head,ctx,expected", SPEC_CASES)
@pytest.mark.parametrize("mode", MODES)
def test_spec_rows(row, base, head, ctx, expected, mode):
    code, tier1, full_plain, full_mand = expected
    if mode == "tier1":
        for mandatory in (False, True):
            assert evaluate(base, head, ctx, mode=mode, mandatory=mandatory) == Decision(
                code, tier1, head.loss_reason or base.loss_reason
            )
    else:
        assert evaluate(base, head, ctx, mode=mode, mandatory=False).blocking is full_plain
        assert evaluate(base, head, ctx, mode=mode, mandatory=True).blocking is full_mand
        assert evaluate(base, head, ctx, mode=mode).code == code


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("loss", LOSS_REASONS)
def test_violation_to_unknown_is_never_repair(mode, loss):
    for ctx in (False, True):
        d = evaluate(_fs("violation"), _fs("unknown", loss, "b"), ctx, mode=mode)
        assert d.code == "unverifiable_violation"
        assert d.blocking is True


@pytest.mark.parametrize("mode", MODES)
def test_pass_to_unknown_syntax_error_blocks(mode):
    d = evaluate(_fs("pass"), _fs("unknown", "syntax_error"), False, mode=mode)
    assert d.blocking is True


def test_loss_reason_preserved():
    for _row, base, head, ctx, _exp in SPEC_CASES[:6]:
        for mode in MODES:
            assert evaluate(base, head, ctx, mode=mode).loss_reason == head.loss_reason


def test_loss_reason_falls_back_to_base():
    d = evaluate(_fs("unknown", "tool_failure"), _fs("absent"), False)
    assert d.code == "removed"
    assert d.loss_reason == "tool_failure"


def test_not_applicable_cannot_carry_loss():
    with pytest.raises(ValueError):
        FactState("not_applicable", loss_reason="tool_failure")


def test_unknown_requires_loss_reason():
    with pytest.raises(ValueError):
        FactState("unknown", "a", "a")


@pytest.mark.parametrize(
    "args",
    [("unknown",), ("pass",), ("violation",), ("violation", "a")],
    ids=["unknown-no-hashes", "pass-no-hashes", "violation-no-hashes", "violation-no-payload"],
)
def test_fact_state_requires_hashes(args):
    kwargs = {"loss_reason": "tool_failure"} if args[0] == "unknown" else {}
    with pytest.raises(ValueError):
        FactState(*args, **kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize("status", ["absent", "not_applicable"])
def test_fact_state_hashes_optional_for_absent_and_na(status):
    assert FactState(status).identity_hash is None  # type: ignore[arg-type]


def test_engine_is_dormant():
    src = Path(__file__).resolve().parents[1] / "src" / "agent_ratchet"
    for name in ("ai_slop_scanner.py", "test_baseline_integrity.py"):
        tree = ast.parse((src / name).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            mods = []
            if isinstance(node, ast.Import):
                mods = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                mods = [("." * node.level) + (node.module or "")]
                mods += [f"{mods[0]}.{a.name}" for a in node.names]
            for m in mods:
                assert not m.endswith("transitions"), (name, m)
