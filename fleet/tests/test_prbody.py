"""The PR body: guard_bump's text with the gate table, hooks line, evidence, deploy line and fleet line."""

from pathlib import Path

import pytest

from guard_fleet.config import Consumer
from guard_fleet.ledger import GATES
from guard_fleet.lockfile import render_lock
from guard_fleet.prbody import render
from guard_fleet.roll import Rolled

P, T = "a1b2c3d4" + "a" * 32, "f" * 40
RUNNING = "0123456789abcdef" + "0" * 24
COMPAT = ("4.x removes `guard_core`; guard test fixtures are exempt only when listed in "
          "`self_skip.fixture_paths`.")


def consumer(pin_kind="req", pin_file="requirements-dev.txt"):
    return Consumer(short="alpha", dir=Path("/srv/alpha"), slug="owner/alpha", default_branch="main",
                    pin_kind=pin_kind, pin_file=pin_file, ring=1, ci="if-run", ci_wait_min=15, deploy_workflows=(),
                    quiet_before_merge=(), commit_env={}, node_modules=False, hook_needs=(), venvs=(),
                    surfaces=frozenset(), confirm_note="")


def rolled(tmp_path, extras="none", gates=None):
    wt = tmp_path / "wt"
    wt.mkdir(exist_ok=True)
    (wt / "guard.lock").write_bytes(render_lock(T, extras))
    gates = gates or {g: ("n/a" if g == "G7" else "PASS", f"/state/v4.0.1/alpha/{g}.log") for g in GATES}
    return Rolled("alpha", "GATED", "gates", "", "c" * 40, "d" * 40, "alpha-1", "hooks: worktree", gates, wt, None)


def body(tmp_path, c=None, extras="none", **kw):
    args = {"version": "4.0.1", "p": P, "t": T, "rolled": rolled(tmp_path, extras), "evidence": ("SKIP x", "BUMP y"),
            "deploy_line": "Merging deploys: deploy.yml on push to main.", "running_tag": "v4.4.0",
            "running_sha": RUNNING, **kw}
    return render(c or consumer(), **args)


def test_pr_body_has_gate_table_hooks_and_fleet_line(tmp_path):
    text = body(tmp_path)
    lines = text.splitlines()
    assert lines[0] == "## Summary"
    assert f"Bump agent-ratchet (formerly guard-core) from `a1b2c3d4` to v4.0.1 (`{T}`)." in lines
    head = lines.index("| gate | verdict | log |")
    assert lines[head + 1] == "|---|---|---|"
    assert lines[head + 2:head + 11] == [
        f"| {g} | {'n/a' if g == 'G7' else 'PASS'} | `/state/v4.0.1/alpha/{g}.log` |" for g in GATES]
    after = lines[head + 11:]
    assert "hooks: worktree" in after
    assert after.index("hooks: worktree") < after.index("- SKIP x") < after.index("- BUMP y") < after.index(
        "Merging deploys: deploy.yml on push to main.")
    assert lines[-1] == "Opened by guard-fleet v4.4.0 (01234567)."
    assert "Claude" not in text and "Generated with" not in text
    assert "Local replica of the CI gate" not in text
    assert lines.index("## Verification") < head


def test_pr_body_commits_for_req_pyproject_and_none(tmp_path):
    req = body(tmp_path)
    assert "Two policy-isolated commits — **merge with a merge commit, never squash**:" in req
    assert "1. `build(deps)`: the dev-dependency pin in `requirements-dev.txt` follows the new SHA." in req
    assert ("2. `chore(guard)` (governance): `guard.lock` and `scripts/guard`, copied byte-for-byte from "
            "`consumer/guard` at v4.0.1.") in req
    assert "test_guard_pin.py" not in req.split("## Verification")[0]   # the fleet does not rewrite the pin test
    pyproject = body(tmp_path, consumer("pyproject", "pyproject.toml"))
    assert "the dev-dependency pin in `pyproject.toml` and `uv.lock` follows the new SHA." in pyproject
    none = body(tmp_path, consumer("none", None))
    assert ("One governance commit (no dev-dependency pin in this repo) — "
            "**merge with a merge commit, never squash**:") in none
    assert "build(deps)" not in none and "Two policy-isolated" not in none


@pytest.mark.parametrize("extras, sentence", [("none", True), ("php", False)])
def test_pr_body_compat_note_drops_the_no_extras_sentence_when_extras_stay(tmp_path, extras, sentence):
    text = body(tmp_path, extras=extras)
    assert COMPAT in text
    assert ("This PR adds no `EXTRAS` line." in text) is sentence
    assert "See the agent-ratchet CHANGELOG for v4.0.1." in text


def test_pr_body_without_deploy_line_or_evidence(tmp_path):
    text = body(tmp_path, deploy_line=None, evidence=())
    assert "Merging deploys" not in text and "- SKIP" not in text
    assert text.endswith("Opened by guard-fleet v4.4.0 (01234567).\n")


def test_pr_body_marks_a_missing_gate(tmp_path):
    r = rolled(tmp_path)
    gates = dict(r.gates)
    del gates["G5"]
    text = render(consumer(), version="4.0.1", p=P, t=T, rolled=Rolled(**{**r.__dict__, "gates": gates}),
                  evidence=(), deploy_line=None, running_tag="v4.4.0", running_sha=RUNNING)
    assert "| G5 | not run |  |" in text
