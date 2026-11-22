from guard_fleet.classify import Level
from guard_fleet.exits import FleetExit
from guard_fleet.exposure import Exposure, TreeScan
from guard_fleet.plan import PlanResult, PlanRow
from guard_fleet.report import EndState, render_end, render_plan
from guard_fleet.target import Target

SHA_P = "a" * 40
SHA_T = "b" * 40
VENV_HINT = "Venvs drifted: pull the main checkouts, then run guard-fleet venvs --refresh"


def _row(short, decision, reason, *, evidence=(), provisional=False, level=Level.CORE, pin_tag="v4.0.0"):
    exposure = Exposure(level, (), TreeScan(frozenset(), ())) if decision != "BLOCKED" else None
    return PlanRow(short, pin_tag, SHA_P, "none", SHA_T, "c" * 40, decision, reason, tuple(evidence), exposure,
                   provisional)


def _result(*rows, note=None):
    return PlanResult(Target("v4.0.1", SHA_T, (4, 0, 1)), tuple(rows), note, FleetExit.OK)


def test_plan_table_lists_every_consumer_with_decision_and_reason():
    out = render_plan(_result(
        _row("alpha", "SKIP", "changed surfaces start at php; exposure is core",
             evidence=("src/agent_ratchet/php/compare.py [php]",)),
        _row("beta", "BUMP", "changed php surface is within exposure php", level=Level.PHP),
        _row("gamma", "BLOCKED", "untagged pin", pin_tag=None),
        _row("delta", "CURRENT", "pin v4.0.1 is at or beyond v4.0.1")))
    lines = out.splitlines()
    assert lines[0] == f"Target v4.0.1 ({SHA_T[:12]})"
    by_short = {ln.split()[0]: ln for ln in lines if ln.split() and ln.split()[0] in ("alpha", "beta", "gamma", "delta")}
    assert "SKIP" in by_short["alpha"] and "core" in by_short["alpha"] and "v4.0.0" in by_short["alpha"]
    assert "BUMP" in by_short["beta"] and "php" in by_short["beta"]
    assert "BLOCKED" in by_short["gamma"] and "untagged pin" in by_short["gamma"]
    assert "CURRENT" in by_short["delta"]
    assert "  alpha: src/agent_ratchet/php/compare.py [php]" in lines      # SKIP evidence is printed


def test_plan_table_marks_provisional_skips_and_the_mirror_note():
    out = render_plan(_result(_row("alpha", "SKIP", "x", provisional=True), note="mirror as of 2026-01-01T00:00:00+00:00"))
    assert "SKIP (provisional)" in out
    assert "mirror as of 2026-01-01T00:00:00+00:00" in out.splitlines()[1]


def test_end_table_refusal_wording_follows_markers():
    s = [EndState("alpha", "BLOCKED G4: scan failed", "guard-fleet release v4.4.1 --rebuild alpha",
                  needs_lock_update=True)]
    plain = render_end(s, markers=False, venv_drift=False)
    assert "Run: ALLOW_GUARD_LOCK_UPDATE=1 guard-fleet release v4.4.1 --rebuild alpha" in plain
    assert VENV_HINT not in plain
    out = render_end(s, markers=True, venv_drift=True)
    assert "ALLOW_GUARD_LOCK_UPDATE=1 guard-fleet" not in out
    assert "Run in your own terminal: guard-fleet release v4.4.1 --rebuild alpha" in out
    assert "It needs ALLOW_GUARD_LOCK_UPDATE=1 set by you, not by an agent." in out
    assert out.rstrip().endswith("guard-fleet venvs --refresh") and out.rstrip().splitlines()[-1] == VENV_HINT


def test_end_table_prints_ordinary_next_commands_unchanged_and_skips_empty_ones():
    s = [EndState("alpha", "LANDED", None),
         EndState("beta", "NOT RUN", "guard-fleet release v4.4.1 --only beta")]
    out = render_end(s, markers=True, venv_drift=False)
    assert "ALLOW_GUARD_LOCK_UPDATE" not in out
    assert "beta: guard-fleet release v4.4.1 --only beta" in out
    assert "alpha: " not in out and "alpha" in out and "LANDED" in out
