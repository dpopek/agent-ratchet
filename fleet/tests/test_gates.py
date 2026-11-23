"""Gates G1-G9 through `roll.prepare`, and the informational `--diff` wrapper (spec 6.7 step 6)."""

import os
from pathlib import Path

import pytest

from fakes import Route
from guard_fleet.difftool import run_diff
from guard_fleet.gates import GateResult
from guard_fleet.ledger import GATES, gated_attempt
from guard_fleet.lockfile import spec_url
from guard_fleet.proc import Result
from guard_fleet.roll import prepare
from repos import _git
from test_roll import TAG, build_env, is_g6, is_trusted, write_junit

T_SRC = {"src/agent_ratchet/__init__.py": b"", "src/agent_ratchet/cli.py": b"def main():\n    return 0\n"}
GOOD_USE = "from agent_ratchet.cli import main\n"
G8_HOOK = ('#!/bin/sh\nif git diff --cached --name-only | grep -qx requirements-dev.txt; then\n'
           "  printf '# added by a hook\\n' >> requirements-dev.txt\n  git add requirements-dev.txt\nfi\n")


class GateRun:
    """The `Rolled` of one `prepare`, plus the runner's calls and the fixture env."""

    def __init__(self, rolled, env):
        self.rolled, self.env, self.calls = rolled, env, env[0].deps.run.calls

    def __getattr__(self, name):
        return getattr(self.rolled, name)


def find_call(r, word):
    found = [c for c in r.calls if word in c[0]]
    assert len(found) == 1, found
    return found[0]


def stray_file(argv, cwd, env):
    (cwd / "stray.txt").write_text("left behind\n")


def hook_mutating_pin(env):
    hook = env.clone / ".git" / "hooks" / "pre-commit"
    hook.write_text(G8_HOOK)
    hook.chmod(0o755)


BREAKERS = {   # gate -> (build kwargs, tweak of the built env)
    "G1": ({}, lambda e: e.routes.insert(0, Route(match=lambda a: is_trusted(a) and "scan" in a, rc=1))),
    "G2": ({}, lambda e: e.routes.insert(0, Route(match=lambda a: is_trusted(a) and "baseline-integrity" in a,
                                                  rc=1))),
    "G3": ({}, lambda e: e.routes.insert(0, Route(match=("sh", "scripts/guard", "version", "--sha"),
                                                  stdout=b"0" * 40 + b"\n"))),
    "G4": ({}, lambda e: e.routes.insert(0, Route(match=("sh", "scripts/guard", "scan"), rc=1))),
    "G5": ({}, lambda e: e.routes.insert(0, Route(match=("sh", "scripts/guard", "baseline-integrity"), rc=1))),
    "G6": ({}, lambda e: e.routes.insert(0, Route(match=is_g6, rc=1, effect=write_junit(
        '<testsuite tests="1" skipped="0" failures="1" errors="0"/>')))),
    "G7": ({"extra_files": {"tools/use.py": "from agent_ratchet.gone import x\n"}}, lambda e: None),
    "G8": ({}, hook_mutating_pin),
    "G9": ({}, lambda e: e.routes.insert(0, Route(match=("sh", "scripts/guard", "scan"), effect=stray_file))),
}


@pytest.fixture
def gate_env(tmp_path, fleet_home):
    def make(consumer="alpha", *, break_gate=None, g6_junit=None, g6_rc=0, extra_files=None, tweak=None):
        kw, breaker = BREAKERS[break_gate] if break_gate else ({}, lambda e: None)
        files = {"tools/use.py": GOOD_USE} if consumer != "gamma" else {}
        files.update(extra_files or {})
        files.update(kw.get("extra_files", {}))
        env = build_env(tmp_path, fleet_home, consumer, extra_files=files, upstream_files=T_SRC)
        breaker(env)
        if g6_junit is not None:
            env.routes.insert(0, Route(match=is_g6, rc=g6_rc, effect=write_junit(g6_junit)))
        if tweak is not None:
            tweak(env)
        return GateRun(prepare(*env), env)
    return make


def gate_records(r):
    records, _ = r.env[0].ledger.records()
    return {x.step: x for x in records if x.attempt == r.attempt and x.step in GATES}


# -- every gate decides on its own -------------------------------------------


def test_all_gates_pass_and_the_attempt_is_gated(gate_env):
    r = gate_env()
    assert (r.state, r.step) == ("GATED", "gates")
    assert {g: v for g, (v, _) in r.gates.items()} == {g: "PASS" for g in GATES}
    records, bad = r.env[0].ledger.records()
    assert gated_attempt(records, bad, "alpha", r.head) == (r.attempt, "")
    by_gate = gate_records(r)
    assert list(by_gate) == list(GATES)
    for gate, rec in by_gate.items():
        assert rec.detail["verdict"] == "PASS" and isinstance(rec.detail["reason"], str)
        assert rec.log == str(r.env.dirs.gate_log(TAG, "alpha", gate)) == r.gates[gate][1]
        assert rec.head == r.head and rec.base == r.base
    trusted = str(r.env.dirs.consumer_dir(TAG, "alpha") / "trusted-guard")
    assert by_gate["G1"].argv[-7:] == ("sh", trusted, "--lock-from", r.base, "scan", "--commit-range",
                                       f"{r.base}..{r.head}")
    assert by_gate["G1"].rc == 0 and by_gate["G7"].rc is None


@pytest.mark.parametrize("gate", GATES)
def test_each_gate_failing_alone_blocks(gate_env, gate):
    rolled = gate_env(break_gate=gate)
    assert rolled.state == "BLOCKED" and rolled.step == gate
    assert [g for g, (v, _) in rolled.gates.items() if v == "FAIL"] == [gate]
    assert list(rolled.gates) == list(GATES)   # a FAIL skips nothing
    records, bad = rolled.env[0].ledger.records()
    assert records[-1].step == "attempt-end" and records[-1].detail == {"ok": False}
    assert records[-1].head == rolled.head
    assert gated_attempt(records, bad, "alpha", rolled.head)[0] is None
    assert gate_records(rolled)[gate].detail["verdict"] == "FAIL"


def test_g1_and_g2_judge_with_base_shim_from_the_state_dir(gate_env):
    r = gate_env()
    trusted = r.env.dirs.consumer_dir(TAG, "alpha") / "trusted-guard"
    assert trusted.read_bytes() == _git_bytes(r.env.clone, f"{r.base}:scripts/guard")
    assert trusted.stat().st_mode & 0o777 == 0o700
    assert not trusted.is_relative_to(r.worktree)
    g2 = [a for a, _, _ in r.calls if is_trusted(a) and "baseline-integrity" in a]
    assert g2 == [("sh", str(trusted), "--lock-from", r.base, "baseline-integrity", "--require-base-ref",
                   "--enforce-policy-isolation", "--commit-range", f"{r.base}..{r.head}")]


def _git_bytes(repo, spec):
    import subprocess
    from repos import _env
    return subprocess.run(("git", "show", spec), cwd=repo, env=_env(), capture_output=True, check=True,
                          stdin=subprocess.DEVNULL, timeout=60).stdout


def test_gate_commands_run_in_the_worktree_with_the_child_env(gate_env):
    r = gate_env()
    gate_calls = [c for c in r.calls if c[0][:1] in (("sh",), ("uv",))]
    assert len(gate_calls) == 6
    for argv, cwd, env in gate_calls:
        assert cwd == r.worktree
        assert env["PATH"] == r.env[0].child_env["PATH"]
    assert [a for a, _, _ in gate_calls if a[:2] == ("sh", "scripts/guard")] == [
        ("sh", "scripts/guard", "version", "--sha"),
        ("sh", "scripts/guard", "scan", "--commit-range", f"{r.base}..{r.head}"),
        ("sh", "scripts/guard", "baseline-integrity", "--require-base-ref", "--enforce-policy-isolation",
         "--commit-range", f"{r.base}..{r.head}")]


def test_gates_are_separate_subprocesses(gate_env):
    r = gate_env()
    assert not any(a[:2] == ("sh", "-c") or "||" in a or "&&" in a for a, _, _ in r.calls)
    assert sum(1 for a, _, _ in r.calls if a[:1] == ("sh",)) == 5


def test_a_fail_prints_the_log_path_and_its_last_30_lines(gate_env):
    def noisy(argv, cwd, env):
        log = env_ref[0].dirs.gate_log(TAG, "alpha", "G4")
        log.parent.mkdir(parents=True, exist_ok=True)
        log.write_text("".join(f"line {i}\n" for i in range(1, 41)))
        return Result(argv, 1, b"", b"", False)

    env_ref = []

    def tweak(e):
        env_ref.append(e)
        e.routes.insert(0, Route(match=("sh", "scripts/guard", "scan"), effect=noisy))

    r = gate_env(tweak=tweak)
    err = r.env[0].deps.err.getvalue()
    log = r.env.dirs.gate_log(TAG, "alpha", "G4")
    assert str(log) in err and "G4" in err
    assert "line 40\n" in err and "line 12\n" in err and "line 11\n" not in err
    assert "G1" not in err   # passing gates print nothing


def test_timed_out_gate_fails(gate_env):
    r = gate_env(tweak=lambda e: e.routes.insert(0, Route(
        match=("sh", "scripts/guard", "baseline-integrity"),
        effect=lambda a, c, env: Result(a, 124, b"", b"", True))))
    assert r.gates["G5"][0] == "FAIL" and r.step == "G5"
    assert "timed out after 1800 s" in gate_records(r)["G5"].detail["reason"]


def test_g3_needs_exactly_t(gate_env):
    r = gate_env(break_gate="G3")
    assert "0000000000" in r.reason and r.env.t in r.reason


# -- G6 ------------------------------------------------------------------------


@pytest.mark.parametrize("rc, junit", [
    (5, '<testsuite tests="0" skipped="0" failures="0" errors="0"/>'),
    (0, '<testsuite tests="0" skipped="0" failures="0" errors="0"/>'),
    (0, '<testsuite tests="2" skipped="0" failures="0" errors="1"/>'),
    (0, "not xml"),
])
def test_pytest_exit_5_and_zero_passed_fail_g6(gate_env, rc, junit):
    r = gate_env(g6_junit=junit, g6_rc=rc)
    assert r.gates["G6"][0] == "FAIL" and r.step == "G6"


def test_g6_all_skipped_junit_fails(gate_env):
    r = gate_env(g6_junit='<testsuite tests="2" skipped="2" failures="0" errors="0"/>', g6_rc=0)
    assert r.gates["G6"][0] == "FAIL"


def test_g6_counts_every_suite_of_a_testsuites_root(gate_env):
    r = gate_env(g6_junit='<testsuites><testsuite tests="1" skipped="1" failures="0" errors="0"/>'
                          '<testsuite tests="1" skipped="0" failures="0" errors="0"/></testsuites>')
    assert r.gates["G6"][0] == "PASS"


def test_g6_does_not_trust_a_stale_junit_file(gate_env):
    def stale(e):
        xml = e.dirs.consumer_dir(TAG, "alpha") / "G6.xml"
        xml.parent.mkdir(parents=True, exist_ok=True)
        xml.write_text('<testsuite tests="3" skipped="0" failures="0" errors="0"/>')
        e.routes.insert(0, Route(match=is_g6))   # rc 0, writes no report
    assert gate_env(tweak=stale).gates["G6"][0] == "FAIL"


def test_g6_missing_pin_test_fails(gate_env):
    r = gate_env(extra_files={"tests/ci/test_guard_pin.py": None})
    assert (r.state, r.step) == ("BLOCKED", "G6")
    assert "pin test missing" in r.reason
    assert not any(is_g6(a) for a, _, _ in r.calls)


def test_g6_runs_isolated(gate_env):
    def no_cache_vars(e):
        for key in ("UV_CACHE_DIR", "XDG_CACHE_HOME"):
            e[0].child_env.pop(key, None)
    r = gate_env(tweak=no_cache_vars)
    argv, cwd, env = find_call(r, "pytest")
    assert "--noconftest" in argv and env["GIT_CONFIG_GLOBAL"] == "/dev/null" and env["HOME"] != os.environ["HOME"]
    assert argv == ("uv", "run", "--isolated", "--no-config", "--no-project", "--with", spec_url(r.env.t, "php"),
                    "--with", "pytest", "python", "-m", "pytest", "-q", "-p", "no:cacheprovider", "--noconftest",
                    "-c", "/dev/null", "--rootdir", ".", "--junitxml",
                    str(r.env.dirs.consumer_dir(TAG, "alpha") / "G6.xml"), "tests/ci/test_guard_pin.py")
    assert env["GIT_CONFIG_NOSYSTEM"] == "1" and env["PYTHONDONTWRITEBYTECODE"] == "1"
    assert env["XDG_CONFIG_HOME"].startswith(str(Path(env["HOME"]).parent))
    assert not Path(env["HOME"]).exists()   # the fresh temp dir is gone afterwards
    assert env["UV_CACHE_DIR"] == str(Path(r.env.home) / ".cache" / "uv")


def test_g6_and_g7_na_for_pin_kind_none_and_no_reference(gate_env):
    r = gate_env(consumer="gamma")            # pin kind none, no agent_ratchet references
    assert r.gates["G6"][0] == "n/a" and r.gates["G7"][0] == "n/a" and r.state == "GATED"
    assert not any(is_g6(a) for a, _, _ in r.calls)


# -- HEAD and the tree ---------------------------------------------------------


def test_head_moved_after_gate_fails_that_gate(gate_env):
    def commit_in_w(argv, cwd, env):
        (cwd / "sneaky.txt").write_text("x\n")
        _git(cwd, "add", "sneaky.txt")
        _git(cwd, "commit", "-q", "-m", "sneaky")

    r = gate_env(tweak=lambda e: e.routes.insert(0, Route(match=("sh", "scripts/guard", "scan"),
                                                          effect=commit_in_w)))
    assert (r.state, r.step) == ("BLOCKED", "G4")
    assert [r.gates[g][0] for g in ("G1", "G2", "G3")] == ["PASS"] * 3
    assert r.gates["G4"][0] == "FAIL" and "HEAD moved" in r.reason
    assert all(r.gates[g][0] == "FAIL" for g in ("G5", "G6", "G7", "G8", "G9"))
    records, _ = r.env[0].ledger.records()
    assert records[-1].head == r.head != _git(r.worktree, "rev-parse", "HEAD")


def test_g9_ignores_only_the_fleets_node_modules_symlink(tmp_path, fleet_home):
    env = build_env(tmp_path, fleet_home, "alpha", node_modules=True, extra_files={"tools/use.py": GOOD_USE},
                    upstream_files=T_SRC)
    r = prepare(*env)
    assert r.state == "GATED" and r.gates["G9"][0] == "PASS"


def test_gate_result_shape():
    g = GateResult("G7", "n/a", "no reference", None, None, Path("/dev/null"))
    assert (g.gate, g.verdict, g.argv, g.rc) == ("G7", "n/a", None, None)


# -- --diff --------------------------------------------------------------------

TOOL = (b'import argparse\np = argparse.ArgumentParser()\np.add_argument("--consumer")\n'
        b'p.add_argument("--new-from", default=None)\n')
TOOL_WITHOUT_NEW_FROM = b'import argparse\np = argparse.ArgumentParser()\np.add_argument("--consumer")\n'


class DiffEnv:
    def __init__(self, env, tool_result):
        self.env, self.mirror, self.tool_result = env, env.up, tool_result
        self.seen: list[tuple[tuple[str, ...], Path, float, bytes | None]] = []
        ctx = env[0]
        fake = ctx.deps.run

        def capture(argv, *, cwd, env, timeout, input=None, log=None):
            if "-I" in argv:
                args = tuple(argv[argv.index("python3"):])
                script = Path(args[2])
                self.seen.append((args, cwd, timeout, script.read_bytes() if script.exists() else None))
                return Result(args, *self.tool_result)
            return fake(argv, cwd=cwd, env=env, timeout=timeout, input=input, log=log)

        ctx.deps.run = capture

    def summary(self, **kw):
        ctx, consumer, row = self.env
        return run_diff(ctx, consumer, base=row.d, p=row.p, t=row.t, extras=row.extras, worktree=self.env.clone,
                        **kw)

    def run(self, **kw):
        self.last_summary = self.summary(**kw)
        argv, cwd, timeout, _ = self.seen[-1]
        return argv, cwd, timeout


@pytest.fixture
def diff_env(tmp_path, fleet_home):
    def make(name="alpha", tool=TOOL, result=(0, b"0 differing case(s)\n", b"", False)):
        env = build_env(tmp_path, fleet_home, name, upstream_files={"tools/differential_findings.py": tool})
        return DiffEnv(env, result)
    return make


def test_diff_tool_runs_isolated_from_temp_copy_with_outer_timeout(diff_env):
    d = diff_env()
    argv, cwd, timeout = d.run()
    assert argv[:2] == ("python3", "-I") and not Path(argv[2]).is_relative_to(d.mirror)
    assert "--timeout" in argv and argv[argv.index("--timeout") + 1] == "600" and timeout == 1800
    assert d.seen[-1][3] == TOOL                 # the extracted bytes are T's tool
    assert not Path(argv[2]).exists()            # the temp copy is removed afterwards
    assert not Path(argv[2]).is_relative_to(d.env.clone) and not Path(argv[2]).is_relative_to(d.env.home)
    ctx, consumer, row = d.env

    def flag(name):
        return argv[argv.index(name) + 1]
    assert flag("--consumer") == str(d.env.clone) and flag("--legacy-ref") == row.d
    assert flag("--guard-sha") == row.t and flag("--commits") == "30"
    assert flag("--legacy-cmd") == (f"uvx --quiet --from git+https://github.com/dpopek/agent-ratchet@{row.p} "
                                    f"agent-ratchet --expect-sha {row.p}")
    assert flag("--out") == str(d.env.dirs.consumer_dir(TAG, "alpha") / "differential")
    assert flag("--new-from") == spec_url(row.t, "php")
    assert d.last_summary.startswith("diff: no differences")


def test_diff_without_extras_passes_no_new_from(diff_env):
    d = diff_env("beta")
    argv, _, _ = d.run()
    assert "--new-from" not in argv


def test_diff_tool_without_new_from_is_reported_for_extras(diff_env):
    d = diff_env(tool=TOOL_WITHOUT_NEW_FROM)
    assert d.summary() == "diff: EXTRAS not supported by the tool"
    assert d.seen == []


@pytest.mark.parametrize("result, expected", [
    ((124, b"", b"", True), "diff: timed out after 90 s"),
    ((1, b"legacy-ref: x\nDIFFERENT scan: scan\n2 differing case(s)\n", b"", False), "diff: 2 differing case(s)"),
    ((2, b"", b"differential: cannot materialise consumer: boom\n", False), "diff: tool error"),
    ((0, b"ERROR: both sides failed identically\n0 differing case(s)\n", b"", False), "diff: tool error"),
])
def test_diff_summaries_never_raise(diff_env, result, expected):
    d = diff_env(result=result)
    summary = d.summary(budget_s=90)
    assert summary.startswith(expected) and "\n" not in summary
    assert d.seen[-1][2] == 90
