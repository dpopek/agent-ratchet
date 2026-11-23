"""Ring order, the canary rule, live ring-2 derivation and the confirmation table (spec 6.8).

The orchestration tests drive `land_rings` through a `StubLander` that honours the Lander contract (ledger records
for verify and push-run, merged_verified read-only); the end-to-end tests use the real Lander on a fixture repo.
"""

import dataclasses
from pathlib import Path
from types import SimpleNamespace

import pytest

from fakes import FakeClock
from guard_fleet.ci import BILLING_PREFIX
from guard_fleet.config import Consumer, FleetConfig
from guard_fleet.gh import GhNetworkError
from guard_fleet.land import Approval, Outcome
from guard_fleet.ledger import Ledger, Record
from guard_fleet.plan import PlanRow
from guard_fleet.rings import (ConsumerState, billing_state, canary_block, deploy_lines, land_rings, rebuild_state,
                               render_confirmation, ring2_ready, triggers_on_push)
from guard_fleet.roll import Rolled
from guard_fleet.target import Target
from test_land import SLUG, _seed_push_run, land_env  # noqa: F401  (the land_env fixture)
from test_roll import TAG

T = "t" * 40
TARGET = Target(TAG, T, (4, 0, 1))
RESUME_RING_2 = f"guard-fleet land {TAG} --ring 2"


def make_consumer(short, ring, ci="if-run", **kw):
    fields = dict(short=short, dir=Path(f"/nonexistent/{short}"), slug=f"owner/{short}", default_branch="main",
                  pin_kind="none", pin_file=None, ring=ring, ci=ci, ci_wait_min=15, deploy_workflows=(),
                  quiet_before_merge=(), commit_env={}, node_modules=False, hook_needs=(), venvs=(),
                  surfaces=frozenset(), confirm_note="")
    fields.update(kw)
    return Consumer(**fields)


@pytest.fixture
def cfg(tmp_path):
    return FleetConfig(tmp_path / "wt", (
        make_consumer("alpha", 1, commit_env={"FLEET_COMMIT_NOTE": "kept"}, confirm_note="alpha is busy"),
        make_consumer("beta", 1, ci="required"),
        make_consumer("gamma", 1),
        make_consumer("delta", 2)))


def landed(short):
    return Outcome(short, "LANDED", "verify", "", f"https://github.com/owner/{short}/pull/1", f"m-{short}", None, False)


class StubLander:
    """What rings.py may call, with the real Lander's observable contract (ledger records, read-only merged_verified)."""

    def __init__(self, tmp_path, cfg, flags=frozenset()):
        self.ledger = Ledger(tmp_path / "ledger.jsonl", FakeClock())
        self.ctx = SimpleNamespace(ledger=self.ledger, cfg=cfg)
        self.approval = Approval(TAG, T, {}, flags)
        self.calls = []
        self.land_result = {}    # short -> Outcome that land_consumer returns instead of LANDED
        self.gate_result = {}    # short -> FAILED Outcome that push_run_gate returns instead of None (pass)
        self.verified = {}       # short -> Outcome that merged_verified returns (default: LANDED if it landed here)
        self.landed = {}

    def _record(self, short, step, verdict, head, **detail):
        self.ledger.record(Record("2026-01-01T00:00:00Z", f"{short}-1", short, step, None, None, "b" * 40, head,
                                  None, {"verdict": verdict, **detail}))

    def land_consumer(self, c, rolled):
        self.calls.append(("land", c.short))
        out = self.land_result.get(c.short) or landed(c.short)
        if out.state == "LANDED":
            self.landed[c.short] = out
            self._record(c.short, "verify", "pass", rolled.head, merge=out.merge_sha)
        return out

    def push_run_gate(self, c, merge_sha):
        self.calls.append(("gate", c.short, merge_sha))
        failed = self.gate_result.get(c.short)
        self._record(c.short, "push-run", "fail" if failed else "pass", "h" * 40, merge=merge_sha)
        return failed

    def reverify_current(self, c, *, canary):
        self.calls.append(("reverify", c.short, canary))
        out = self.merged_verified(c)
        if out.state == "LANDED" and canary:
            return self.push_run_gate(c, out.merge_sha) or out
        return out

    def merged_verified(self, c):
        self.calls.append(("merged_verified", c.short))
        if c.short in self.verified:
            return self.verified[c.short]
        return self.landed.get(c.short) or Outcome(c.short, "BLOCKED", "verify", "no merged fleet PR", None, None,
                                                   None, False)

    def names(self, kind):
        return [c[1] for c in self.calls if c[0] == kind]


@pytest.fixture
def stub(tmp_path, cfg):
    return StubLander(tmp_path, cfg)


def plan_row(short, decision="BUMP", reason=""):
    return PlanRow(short, "v4.0.0", "p" * 40, "none", T, "d" * 40, decision, reason, (), None, False)


def make_rolled(short, state="GATED", reason=""):
    gates = {"G1": ("pass", f"/logs/{short}/G1.log")} if state == "GATED" else {}
    return Rolled(short, state, "gates" if state == "GATED" else "c2", reason, "b" * 40, "h" * 40, f"{short}-1",
                  "hooks: worktree", gates, None, None)


def make_states(cfg, stub, *, decisions=None, roll=None, drop=()):
    """One ConsumerState per consumer (plan + roll as `prepare` left them); BUMP consumers start a ledger attempt."""
    states = []
    for c in cfg.consumers:
        if c.short in drop:
            continue
        decision = (decisions or {}).get(c.short, "BUMP")
        rolled = None
        if decision == "BUMP":
            stub.ledger.start_attempt(c.short, "b" * 40)
            rolled = make_rolled(c.short, (roll or {}).get(c.short, "GATED"), "boom")
        states.append(ConsumerState(c.short, c.ring, plan_row(c.short, decision), rolled, None))
    return states


def run(stub, cfg, states, *, rings=(1, 2), hold=False):
    return land_rings(stub, cfg, TARGET, states, rings=rings, hold_ring_2=hold)


def by_short(states):
    return {s.short: s for s in states}


# -- order and the canary ----------------------------------------------------------------------------------------


def test_ring1_lands_the_canary_first_then_the_rest_in_file_order_then_ring_2(stub, cfg):
    out = by_short(run(stub, cfg, make_states(cfg, stub)))
    assert [c[:2] for c in stub.calls if c[0] in ("land", "gate")] == [
        ("land", "beta"), ("gate", "beta"), ("land", "alpha"), ("land", "gamma"), ("land", "delta")]
    assert all(s.outcome.state == "LANDED" for s in out.values())


def test_no_non_canary_push_before_the_canary_push_run_gate_passed(stub, cfg):
    run(stub, cfg, make_states(cfg, stub))
    kinds = [c[:2] for c in stub.calls]
    assert kinds.index(("gate", "beta")) < kinds.index(("land", "alpha")) < kinds.index(("land", "gamma"))
    assert stub.calls[0][:2] == ("land", "beta")


def test_no_ring1_merge_while_canary_unlanded(stub, cfg):
    out = by_short(run(stub, cfg, make_states(cfg, stub, roll={"beta": "BLOCKED"})))
    assert stub.names("land") == [] and stub.names("gate") == []
    for short in ("beta", "alpha", "gamma"):
        assert out[short].outcome.state == "BLOCKED"
    assert "BLOCKED at roll" in out["alpha"].outcome.reason and "beta" in out["alpha"].outcome.reason
    assert out["delta"].outcome.state == "BLOCKED"   # ring 2 is not reached either


def test_canary_blocked_at_land_blocks_the_other_ring1_consumers(stub, cfg):
    stub.land_result["beta"] = Outcome("beta", "BLOCKED", "ci", "ci: pending", None, None, None, True)
    out = by_short(run(stub, cfg, make_states(cfg, stub)))
    assert stub.names("land") == ["beta"] and stub.names("gate") == []
    assert out["beta"].outcome.step == "ci"
    assert out["alpha"].outcome.state == "BLOCKED" and "canary beta is BLOCKED at ci" in out["alpha"].outcome.reason


def test_only_without_the_canary_blocks_the_other_ring1_consumers(stub, cfg):
    out = by_short(run(stub, cfg, make_states(cfg, stub, drop=("beta",))))
    assert stub.names("land") == []
    assert "--only" in out["alpha"].outcome.reason and "beta" in out["alpha"].outcome.reason


def test_canary_skip_says_no_canary_ran_and_ring1_proceeds(stub, cfg):
    states = make_states(cfg, stub, decisions={"beta": "SKIP"})
    table = render_confirmation(TARGET, "f" * 40, states, prs_to_open=[], prs_to_close=[], canary_order=["beta"],
                                deploy_lines=[], billing="Actions billing: ok", notes={}, diff_lines=[],
                                rebuild_commits={}, cfg=cfg)
    assert "no canary ran" in table
    assert canary_block(cfg, states) is None
    out = by_short(run(stub, cfg, states))
    assert stub.names("land") == ["alpha", "gamma", "delta"] and stub.names("gate") == []
    assert out["beta"].outcome is None and out["delta"].outcome.state == "LANDED"


def test_canary_current_is_reverified_live_including_its_push_run_gate(stub, cfg):
    stub.verified["beta"] = landed("beta")
    out = by_short(run(stub, cfg, make_states(cfg, stub, decisions={"beta": "CURRENT"})))
    assert stub.calls[0] == ("reverify", "beta", True)
    assert ("gate", "beta", "m-beta") in stub.calls and out["beta"].outcome.state == "LANDED"
    assert stub.names("land") == ["alpha", "gamma", "delta"]


def test_a_failed_canary_push_run_stops_the_run_before_any_other_merge(stub, cfg):
    failed = Outcome("beta", "FAILED", "push-run", "push-run: governance failed", None, "m-beta", None, False)
    stub.gate_result["beta"] = failed
    out = by_short(run(stub, cfg, make_states(cfg, stub)))
    assert stub.names("land") == ["beta"]
    assert (out["beta"].outcome.state, out["beta"].outcome.step) == ("FAILED", "push-run")
    assert out["beta"].outcome.pr_url == landed("beta").pr_url   # the landed PR url survives the replacement
    for short in ("alpha", "gamma", "delta"):
        assert out[short].outcome.state == "NOT_RUN" and "beta" in out[short].outcome.reason


def test_a_failed_consumer_after_the_canary_stops_the_rest_of_the_run(stub, cfg):
    stub.land_result["alpha"] = Outcome("alpha", "FAILED", "verify", "verify: lock moved", None, "m-alpha", None, False)
    out = by_short(run(stub, cfg, make_states(cfg, stub)))
    assert stub.names("land") == ["beta", "alpha"]
    assert [out[s].outcome.state for s in ("beta", "alpha", "gamma", "delta")] == [
        "LANDED", "FAILED", "NOT_RUN", "NOT_RUN"]


def test_a_blocked_non_canary_does_not_stop_the_other_consumers(stub, cfg):
    stub.land_result["alpha"] = Outcome("alpha", "BLOCKED", "ci", "ci: pending", None, None, "guard-fleet land", True)
    out = by_short(run(stub, cfg, make_states(cfg, stub)))
    assert stub.names("land") == ["beta", "alpha", "gamma", "delta"]
    assert out["alpha"].outcome.state == "BLOCKED" and out["delta"].outcome.state == "LANDED"


def test_plan_blocked_and_unrolled_consumers_become_blocked_states(stub, cfg):
    states = make_states(cfg, stub, decisions={"gamma": "BLOCKED"})
    states[0] = dataclasses.replace(states[0], rolled=None)   # alpha: a BUMP that was never rolled
    out = by_short(run(stub, cfg, states))
    assert out["gamma"].outcome.state == "BLOCKED" and "plan" in out["gamma"].outcome.reason
    assert out["alpha"].outcome.state == "BLOCKED" and "not rolled" in out["alpha"].outcome.reason
    assert stub.names("land") == ["beta", "delta"]


def test_hold_ring_2_marks_held_and_prints_the_command(stub, cfg):
    out = by_short(run(stub, cfg, make_states(cfg, stub), hold=True))
    assert stub.names("land") == ["beta", "alpha", "gamma"]
    assert out["delta"].outcome.state == "HELD" and out["delta"].outcome.next_command == RESUME_RING_2
    assert stub.names("merged_verified") == []   # the hold needs no ring-2 derivation


def test_ring_2_only_run_derives_readiness_from_the_ledger_and_live_state(stub, cfg):
    run(stub, cfg, make_states(cfg, stub), rings=(1,))
    assert stub.names("land") == ["beta", "alpha", "gamma"]
    fresh = make_states(cfg, stub, decisions={"alpha": "SKIP", "beta": "SKIP", "gamma": "SKIP"})
    stub.calls.clear()
    out = by_short(run(stub, cfg, fresh, rings=(2,)))
    assert stub.names("land") == ["delta"] and out["delta"].outcome.state == "LANDED"
    assert stub.names("gate") == []


def test_ring_2_is_refused_with_a_resume_command_when_not_ready(stub, cfg):
    stub.verified["alpha"] = Outcome("alpha", "FAILED", "verify", "verify: lock moved", None, "m", None, False)
    out = by_short(run(stub, cfg, make_states(cfg, stub)))
    assert out["delta"].outcome.state == "BLOCKED" and "alpha" in out["delta"].outcome.reason
    assert out["delta"].outcome.next_command == RESUME_RING_2
    assert "delta" not in stub.names("land")


def test_rebuild_blocked_never_escapes_it_becomes_a_blocked_state(stub, cfg):
    def refuse(consumer):
        from guard_fleet.land import RebuildBlocked
        raise RebuildBlocked(f"rebuild: {consumer.short} is not only the fleet's bump")
    stub.rebuild_local = refuse
    state = make_states(cfg, stub)[0]
    out = rebuild_state(stub, cfg.by_short("alpha"), state)
    assert out.outcome.state == "BLOCKED" and out.outcome.step == "rebuild" and "only the fleet's" in out.outcome.reason
    final = by_short(run(stub, cfg, [out, *make_states(cfg, stub)[1:]]))
    assert final["alpha"].outcome.step == "rebuild"   # land_rings leaves a settled state alone
    assert "alpha" not in stub.names("land")


# -- canary_block ------------------------------------------------------------------------------------------------


def test_canary_block_reasons(stub, cfg):
    skip = make_states(cfg, stub, decisions={"beta": "SKIP"})
    assert canary_block(cfg, skip) is None
    assert "BLOCKED at roll" in canary_block(cfg, make_states(cfg, stub, roll={"beta": "BLOCKED"}))
    assert "--only" in canary_block(cfg, make_states(cfg, stub, drop=("beta",)))
    pending = make_states(cfg, stub)
    assert "NOT RUN" in canary_block(cfg, pending)
    failed = [dataclasses.replace(s, outcome=Outcome("beta", "FAILED", "push-run", "x", None, None, None, False))
              if s.short == "beta" else s for s in pending]
    assert "FAILED at push-run" in canary_block(cfg, failed)
    ok = [dataclasses.replace(s, outcome=landed("beta")) if s.short == "beta" else s for s in pending]
    assert canary_block(cfg, ok) is None


# -- ring2_ready -------------------------------------------------------------------------------------------------


def seed_landed_ring1(stub, *, push_run=True):
    for short in ("beta", "alpha", "gamma"):
        stub.ledger.start_attempt(short, "b" * 40)
        stub.landed[short] = landed(short)
    if push_run:
        stub._record("beta", "push-run", "pass", "h" * 40, merge="m-beta")


def test_ring2_ready_when_ring1_is_verified_and_the_canary_gate_is_green(stub, cfg):
    seed_landed_ring1(stub)
    assert ring2_ready(stub, cfg, TARGET) == (True, "")


def test_ring2_ready_is_read_only(stub, cfg):
    seed_landed_ring1(stub)
    ring2_ready(stub, cfg, TARGET)
    assert {c[0] for c in stub.calls} == {"merged_verified"}   # no land, no gate, no reverify (cleanup)


def test_ring2_refused_after_a_failure_recorded_by_another_process(stub, cfg):
    seed_landed_ring1(stub)
    other = StubLander(stub.ledger.path.parent, cfg)   # another process: same ledger file, no shared memory
    other._record("alpha", "verify", "fail", "a" * 40)
    ready, why = ring2_ready(stub, cfg, TARGET)
    assert ready is False and "alpha" in why and "FAILED" in why


def test_a_later_pass_for_the_same_head_clears_a_recorded_failure_another_head_does_not(stub, cfg):
    seed_landed_ring1(stub)
    stub._record("alpha", "push-run", "fail", "a" * 40)
    assert ring2_ready(stub, cfg, TARGET)[0] is False
    stub._record("alpha", "push-run", "pass", "e" * 40)   # another head
    assert ring2_ready(stub, cfg, TARGET)[0] is False
    stub._record("alpha", "push-run", "pass", "a" * 40)
    assert ring2_ready(stub, cfg, TARGET) == (True, "")


def test_ring2_refused_when_a_live_verify_fails(stub, cfg):
    seed_landed_ring1(stub)
    stub.verified["gamma"] = Outcome("gamma", "FAILED", "verify", "verify: lock moved", None, "m", None, False)
    ready, why = ring2_ready(stub, cfg, TARGET)
    assert ready is False and "gamma" in why


def test_blocked_ring1_consumer_does_not_hold_ring2(stub, cfg):
    seed_landed_ring1(stub)
    del stub.landed["alpha"]   # alpha has no merged fleet PR: merged_verified says BLOCKED
    assert ring2_ready(stub, cfg, TARGET) == (True, "")


def test_ring2_refused_when_the_canary_landed_without_a_green_push_run(stub, cfg):
    seed_landed_ring1(stub, push_run=False)
    ready, why = ring2_ready(stub, cfg, TARGET)
    assert ready is False and "beta" in why and "push-run" in why
    stub._record("beta", "push-run", "pass", "h" * 40, merge="another-merge")   # a gate for another merge
    assert ring2_ready(stub, cfg, TARGET)[0] is False


def test_ring2_refused_when_the_canary_is_an_unlanded_bump(stub, cfg):
    seed_landed_ring1(stub)
    del stub.landed["beta"]   # an attempt exists, but nothing merged
    ready, why = ring2_ready(stub, cfg, TARGET)
    assert ready is False and "beta" in why


def test_ring2_ready_when_the_canary_never_ran_a_skip(stub, cfg):
    for short in ("alpha", "gamma"):
        stub.ledger.start_attempt(short, "b" * 40)
        stub.landed[short] = landed(short)
    assert ring2_ready(stub, cfg, TARGET) == (True, "")


def test_ring2_ready_lets_network_and_auth_errors_propagate(stub, cfg):
    seed_landed_ring1(stub)

    def boom(c):
        raise GhNetworkError(None, "network lost")
    stub.merged_verified = boom
    with pytest.raises(GhNetworkError):
        ring2_ready(stub, cfg, TARGET)


# -- the real Lander end to end ----------------------------------------------------------------------------------


@pytest.fixture
def real_rings(land_env, monkeypatch):  # noqa: F811
    """alpha as the ring-1 canary (ci = required) on the real Lander; its PR gets a green check."""
    canary = dataclasses.replace(land_env.alpha, ci="required")
    cfg = FleetConfig(land_env.ctx.cfg.worktree_root, (canary,))
    orig = land_env.fake._pr_create

    def with_green_check(argv, slug, env):
        res = orig(argv, slug, env)
        land_env.fake.prs[slug][-1]["statusCheckRollup"] = [
            {"__typename": "CheckRun", "name": "CI", "status": "COMPLETED", "conclusion": "SUCCESS",
             "startedAt": "2026-01-01T00:00:00Z"}]
        return res
    monkeypatch.setattr(land_env.fake, "_pr_create", with_green_check)
    state = ConsumerState("alpha", 1, land_env.row, land_env.rolled, None)
    return SimpleNamespace(env=land_env, cfg=cfg, states=[state])


def test_canary_push_run_gate_runs_through_the_real_lander_before_ring_2_is_derived(real_rings):
    env = real_rings.env
    original = env.fake._run_list

    def seeded(argv, slug, e):   # the push run appears only once the merge exists
        merge = _merge_sha(env)
        if merge and "--event" in argv:
            _seed_push_run(env, merge, other="success")
        return original(argv, slug, e)
    env.fake._run_list = seeded
    out = land_rings(env.lander, real_rings.cfg, env.lander.ctx.target, real_rings.states, rings=(1, 2),
                     hold_ring_2=False)
    assert out[0].outcome.state == "LANDED"
    assert [r.detail["verdict"] for r in env.records("push-run")] == ["pass"]
    before = len(env.calls)
    assert ring2_ready(env.lander, real_rings.cfg, env.lander.ctx.target) == (True, "")
    new = [a for a, _, _ in env.calls[before:]]
    assert not [a for a in new if a[:1] == ("gh",) and (a[1:3] in (("pr", "merge"), ("pr", "close"),
                                                                    ("pr", "create")) or "-X" in a)]
    assert not [a for a in new if a[:1] == ("git",) and any(w in a for w in ("push", "branch", "worktree"))]


def test_a_failing_canary_push_run_is_failed_and_ring_2_derivation_refuses(real_rings):
    env = real_rings.env
    out = land_rings(env.lander, real_rings.cfg, env.lander.ctx.target, real_rings.states, rings=(1,),
                     hold_ring_2=False)
    assert (out[0].outcome.state, out[0].outcome.step) == ("FAILED", "push-run")   # no push run within the wait
    ready, why = ring2_ready(env.lander, real_rings.cfg, env.lander.ctx.target)
    assert ready is False and "alpha" in why


def _merge_sha(env):
    pr = next((p for p in env.fake.prs.get(SLUG, []) if p.get("state") == "MERGED"), None)
    return pr["mergeCommit"]["oid"] if pr else None


def test_rebuild_state_resets_and_rolls_afresh_on_the_real_lander(land_env):  # noqa: F811
    state = ConsumerState("alpha", 1, land_env.row, land_env.rolled, None)
    assert land_env.wt.exists()
    out = rebuild_state(land_env.lander, land_env.alpha, state)
    assert out.outcome is None and out.rolled is not None and out.rolled.state == "GATED"
    assert out.rolled.attempt != land_env.rolled.attempt   # a fresh roll, not the old one


def test_rebuild_state_blocks_on_a_change_the_fleet_did_not_write(land_env):  # noqa: F811
    (land_env.wt / "stray.txt").write_text("mine\n")
    state = ConsumerState("alpha", 1, land_env.row, land_env.rolled, None)
    out = rebuild_state(land_env.lander, land_env.alpha, state)
    assert (out.outcome.state, out.outcome.step) == ("BLOCKED", "rebuild") and "stray.txt" in out.outcome.reason
    assert out.rolled is land_env.rolled


# -- the confirmation table --------------------------------------------------------------------------------------


def test_confirmation_table_lists_everything(stub, cfg):
    states = make_states(cfg, stub, decisions={"gamma": "SKIP"})
    table = render_confirmation(
        TARGET, "f" * 40, states, prs_to_open=["alpha: bump agent-ratchet to v4.0.1"],
        prs_to_close=["alpha: #7 superseded by the new PR"], canary_order=["beta"],
        deploy_lines=["alpha: merging deploys to production (deploy.yml on push to main)"],
        billing="Actions billing: ok", notes={"alpha": "alpha is busy"}, diff_lines=["diff: README only"],
        rebuild_commits={"alpha": ["a" * 40 + " build(deps): pin agent-ratchet v4.0.1"]}, cfg=cfg)
    for needle in ("v4.0.1", T, "f" * 12, "G1", "hooks: worktree", "commit_env", "FLEET_COMMIT_NOTE=kept",
                   "superseded", "canary order: beta", "billing", "Actions billing: ok", "alpha is busy",
                   "diff: README only", "deploy.yml on push to main", "--rebuild", "build(deps): pin",
                   "required", "SKIP", "BUMP", "RING"):
        assert needle in table, needle
    assert "no canary ran" not in table


def test_confirmation_table_for_a_bare_run_still_names_every_section(stub, cfg):
    table = render_confirmation(TARGET, "f" * 40, make_states(cfg, stub), prs_to_open=[], prs_to_close=[],
                                canary_order=[], deploy_lines=[], billing="Actions billing: ok", notes={},
                                diff_lines=[], rebuild_commits={})
    for needle in ("PRs to open", "superseded", "canary", "Deploy:", "billing", "commit_env"):
        assert needle in table, needle


# -- deploy lines and billing ------------------------------------------------------------------------------------

PUSH_MAIN = "name: Deploy\non:\n  push:\n    branches: [main]\njobs: {}\n"


@pytest.mark.parametrize("text, expected", [
    (PUSH_MAIN, True),
    ("on:\n  push:\n    branches:\n      - main\n      - release/*\n", True),
    ("on:\n  push:\n    branches: ['rel*', 'ma*']\n", True),
    ("on:\n  push:\n    branches: [develop]\n", False),
    ("on:\n  push:\n    branches-ignore: [main]\n", False),
    ("on:\n  push:\n    branches-ignore: [develop]\n", True),
    ("on:\n  push:\n    tags: ['v*']\n", False),
    ("on:\n  push:\n", True),
    ("on: push\n", True),
    ("on: [push, workflow_dispatch]\n", True),
    ("on: [pull_request]\n", False),
    ("on:\n  - push\n", True),
    ("on:\n  workflow_dispatch:\n  pull_request:\n    branches: [main]\n", False),
    ('"on":\n  push:\n    branches: [main]  # deploy\n', True),
    ("name: x\njobs:\n  push:\n    runs-on: x\n", False),
    ("", False),
])
def test_triggers_on_push_to_the_default_branch(text, expected):
    assert triggers_on_push(text, "main") is expected


def test_deploy_line_from_live_trigger_and_state(land_env):  # noqa: F811
    d = land_env.move_main({".github/workflows/deploy.yml": PUSH_MAIN, ".github/workflows/manual.yml":
                            "on: workflow_dispatch\n", ".github/workflows/off.yml": PUSH_MAIN})
    alpha = dataclasses.replace(land_env.alpha, deploy_workflows=("deploy.yml", "manual.yml", "off.yml", "gone.yml"))
    cfg = FleetConfig(land_env.ctx.cfg.worktree_root, (alpha,))
    fake = land_env.fake
    fake.workflows.update({(SLUG, "deploy.yml"): "active", (SLUG, "manual.yml"): "active",
                           (SLUG, "off.yml"): "disabled_manually"})
    fake.runs[SLUG] = [{"databaseId": 3, "headBranch": "main", "workflowFile": "deploy.yml", "status": "queued",
                        "conclusion": None, "event": "push"},
                       {"databaseId": 2, "headBranch": "main", "workflowFile": "deploy.yml", "status": "completed",
                        "conclusion": "success", "event": "push"}]
    lines = deploy_lines(land_env.ctx.gh, cfg, {"alpha": d})
    assert "alpha: merging deploys to production (deploy.yml on push to main)" in lines
    assert not [ln for ln in lines if "merging deploys" in ln and ("manual.yml" in ln or "off.yml" in ln)]
    assert any("deploy.yml" in ln and "active" in ln and "queued" in ln for ln in lines)   # the deploy queue
    assert any("off.yml" in ln and "disabled_manually" in ln for ln in lines)
    assert any("gone.yml" in ln and "not found" in ln for ln in lines)


def test_billing_state_reads_the_newest_default_branch_run(land_env):  # noqa: F811
    fake = land_env.fake
    gh = land_env.ctx.gh
    cfg = FleetConfig(land_env.ctx.cfg.worktree_root, (land_env.alpha,))
    assert billing_state(gh, cfg) == "Actions billing: ok"   # no runs at all
    fake.runs[SLUG] = [{"databaseId": 20, "headBranch": "main", "status": "completed", "conclusion": "failure"}]
    job = {"id": 5, "run_id": 20, "name": "tests", "status": "completed", "conclusion": "failure", "runner_id": 0,
           "runner_name": "", "runner_group_id": 0, "steps": []}
    fake.jobs[5] = job
    fake.annotations[5] = [{"annotation_level": "failure", "message": BILLING_PREFIX + ". Check your billing."}]
    assert billing_state(gh, cfg) == "Actions billing blocked: alpha"
    fake.annotations[5] = [{"annotation_level": "failure", "message": "Process completed with exit code 1."}]
    assert billing_state(gh, cfg) == "Actions billing: ok"
    fake.jobs[5] = {**job, "runner_id": 7, "runner_name": "r", "steps": [{"name": "x"}]}
    fake.annotations[5] = [{"annotation_level": "failure", "message": BILLING_PREFIX}]
    assert billing_state(gh, cfg) == "Actions billing: ok"   # a job that ran is not a billing refusal
