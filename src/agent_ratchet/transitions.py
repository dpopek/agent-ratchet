"""Paired BASE/HEAD transition engine (dormant: nothing in the scanner imports it).

The rule table is data; the first matching rule wins. Rows may overlap by
design (for example payload and context both changed), so evaluation order is
the tie-break.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

Outcome = Literal["pass", "violation", "unknown", "not_applicable"]
LossReason = Literal[
    "syntax_error",
    "missing_tier2_index",
    "tool_failure",
    "coverage_gap",
    "release_state_unknown",
]
Status = Literal["pass", "violation", "unknown", "not_applicable", "absent"]

DecisionCode = Literal[
    "pass",
    "unchanged_unknown",
    "needs_tier2_verification",
    "context_mutated_unknown",
    "degraded_epistemic",
    "incomplete",
    "unverifiable_violation",
    "violation",
    "unchanged_violation",
    "removed",
    "not_applicable",
]
When = Literal["any", "same", "payload_changed", "context_changed", "syntax_error", "other_loss"]
Mode = Literal["tier1", "full_ci"]


@dataclass(frozen=True)
class FactState:
    status: Status
    identity_hash: str | None = None
    payload_hash: str | None = None
    context_hash: str | None = None
    loss_reason: LossReason | None = None

    def __post_init__(self) -> None:
        if self.status == "unknown" and self.loss_reason is None:
            raise ValueError("unknown status requires a loss_reason")
        if self.status == "not_applicable" and self.loss_reason is not None:
            raise ValueError("not_applicable is never a substitute for a loss_reason")
        if self.status not in ("absent", "not_applicable") and (self.identity_hash is None or self.payload_hash is None):
            raise ValueError(f"{self.status} status requires identity_hash and payload_hash")


@dataclass(frozen=True)
class Decision:
    code: DecisionCode
    blocking: bool
    loss_reason: LossReason | None


@dataclass(frozen=True)
class Rule:
    base: frozenset[Status]
    head: frozenset[Status]
    when: When
    code: DecisionCode
    tier1_blocking: bool
    full_ci_blocking: Literal[True, False, "mandatory"]


_ANY: frozenset[Status] = frozenset({"pass", "violation", "unknown", "not_applicable", "absent"})


def _r(base, head, when, code, tier1, full_ci) -> Rule:
    return Rule(frozenset(base), frozenset(head), when, code, tier1, full_ci)


TRANSITIONS: tuple[Rule, ...] = (
    _r({"unknown"}, {"unknown"}, "payload_changed", "needs_tier2_verification", False, True),
    _r({"unknown"}, {"unknown"}, "context_changed", "context_mutated_unknown", False, True),
    _r({"unknown"}, {"unknown"}, "same", "unchanged_unknown", False, "mandatory"),
    _r({"pass"}, {"unknown"}, "syntax_error", "degraded_epistemic", True, True),
    _r({"pass"}, {"unknown"}, "other_loss", "incomplete", False, "mandatory"),
    _r({"violation"}, {"unknown"}, "any", "unverifiable_violation", True, True),
    _r(_ANY, {"pass"}, "any", "pass", False, False),
    _r({"pass", "violation", "unknown", "not_applicable"}, {"absent"}, "any", "removed", False, False),
    _r({"absent", "not_applicable"}, {"unknown"}, "any", "needs_tier2_verification", False, True),
    _r({"violation"}, {"violation"}, "same", "unchanged_violation", False, False),
    _r(_ANY, {"violation"}, "any", "violation", True, True),
    _r(_ANY, {"not_applicable"}, "any", "not_applicable", False, False),
    _r({"absent"}, {"absent"}, "any", "not_applicable", False, False),
)


def _payload_changed(base: FactState, head: FactState) -> bool:
    return base.identity_hash != head.identity_hash or base.payload_hash != head.payload_hash


def _when_holds(when: When, base: FactState, head: FactState, ctx_delta: bool) -> bool:
    if when == "any":
        return True
    changed = _payload_changed(base, head)
    if when == "payload_changed":
        return changed
    if when == "context_changed":
        return ctx_delta
    if when == "same":
        return not changed and not ctx_delta
    if when == "syntax_error":
        return head.loss_reason == "syntax_error"
    return head.loss_reason is not None and head.loss_reason != "syntax_error"


def _matching_rules(base: FactState, head: FactState, ctx_delta: bool) -> list[Rule]:
    return [
        rule
        for rule in TRANSITIONS
        if base.status in rule.base
        and head.status in rule.head
        and _when_holds(rule.when, base, head, ctx_delta)
    ]


def evaluate(
    base: FactState,
    head: FactState,
    ctx_delta: bool,
    *,
    mode: Mode = "tier1",
    mandatory: bool = False,
) -> Decision:
    matches = _matching_rules(base, head, ctx_delta)
    if not matches:
        raise ValueError(f"no transition rule for {base.status} -> {head.status}")
    rule = matches[0]
    flag = rule.tier1_blocking if mode == "tier1" else rule.full_ci_blocking
    blocking = mandatory if flag == "mandatory" else flag
    return Decision(rule.code, blocking, head.loss_reason or base.loss_reason)
