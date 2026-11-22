"""Plain-text tables: the `plan` table and the end-of-run table."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from .env import refusal_lines
from .plan import PlanResult

VENV_DRIFT_HINT = "Venvs drifted: pull the main checkouts, then run guard-fleet venvs --refresh"


@dataclass(frozen=True)
class EndState:
    short: str
    state: str
    next_command: str | None
    needs_lock_update: bool = False   # the next command must be run with the lock-update variable set by the operator


def _table(header: Sequence[str], rows: Sequence[Sequence[str]]) -> list[str]:
    grid = [list(header), *map(list, rows)]
    widths = [max(len(r[i]) for r in grid) for i in range(len(header))]
    return [("  ".join(cell.ljust(w) for cell, w in zip(r, widths))).rstrip() for r in grid]


def render_plan(res: PlanResult) -> str:
    lines = [f"Target {res.target.tag} ({res.target.sha[:12]})"]
    if res.mirror_note:
        lines.append(res.mirror_note)
    rows = []
    for r in res.rows:
        decision = f"{r.decision} (provisional)" if r.provisional else r.decision
        exposure = r.exposure.level.name.lower() if r.exposure is not None else "-"
        rows.append((r.short, r.pin_tag or "-", exposure, decision, r.reason))
    lines += _table(("CONSUMER", "PIN", "EXPOSURE", "DECISION", "WHY"), rows)
    for r in res.rows:
        lines += [f"  {r.short}: {line}" for line in r.evidence]
    return "\n".join(lines) + "\n"


def render_end(states: Sequence[EndState], *, markers: bool, venv_drift: bool) -> str:
    lines = _table(("CONSUMER", "STATE"), [(s.short, s.state) for s in states])
    nexts = [s for s in states if s.next_command]
    if nexts:
        lines.append("")
        lines.append("Next:")
    for s in nexts:
        assert s.next_command is not None
        said = refusal_lines(s.next_command, markers=markers) if s.needs_lock_update else [s.next_command]
        lines.append(f"  {s.short}: {said[0]}")
        lines += [f"    {extra}" for extra in said[1:]]
    if venv_drift:
        lines += ["", VENV_DRIFT_HINT]
    return "\n".join(lines) + "\n"
