"""Gate inputs: the paths whose change invalidates the local gates (spec 6.7, used by land's base-moved rule)."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from fakes import real_git
from guard_fleet import gate_inputs as gi
from guard_fleet.config import Consumer
from guard_fleet.lockfile import spec_url
from guard_fleet.proc import Result
from repos import _git, commit_files, make_bare, make_clone

P, T = "a" * 40, "b" * 40


class AskRunner:
    """Answers the ASK_SCRIPT call per spec: `flags[spec]` is the set that release would flag."""

    def __init__(self, flags, rc=0, stdout=None):
        self.flags, self.rc, self.stdout = flags, rc, stdout
        self.calls = []

    def __call__(self, argv, *, cwd, env, timeout, input=None, log=None):
        args = tuple(argv)
        i = args.index("uv")
        args = args[i:]
        self.calls.append((args, cwd, json.loads(input)))
        spec = args[args.index("--with") + 1]
        out = self.stdout if self.stdout is not None else json.dumps(
            sorted(p for p in json.loads(input) if p in self.flags[spec])).encode()
        return Result(args, self.rc, out, b"", False)


def consumer(tmp_path, pin_kind="req", pin_file="requirements-dev.txt"):
    return Consumer(short="alpha", dir=tmp_path, slug="owner/alpha", default_branch="main", pin_kind=pin_kind,
                    pin_file=pin_file, ring=1, ci="if-run", ci_wait_min=15, deploy_workflows=(),
                    quiet_before_merge=(), commit_env={}, node_modules=False, hook_needs=(), venvs=(),
                    surfaces=frozenset(), confirm_note="")


@pytest.fixture
def repo(tmp_path, fleet_home):
    work = make_clone(make_bare(tmp_path / "gh", "alpha"), tmp_path / "alpha")
    commit_files(work, "base", {"README": "x\n", "scripts/audit/a.py": "1\n", "tests/ci/test_guard_pin.py": "2\n",
                                "src/app.py": "3\n"})
    base = _git(work, "rev-parse", "HEAD")
    commit_files(work, "moved", {"src/app.py": "4\n", "package.json": "{}\n", ".github/workflows/ci.yml": "x\n",
                                 "tests/ci/new_case.py": "5\n"})
    return work, base, _git(work, "rev-parse", "HEAD")


def test_gate_inputs_asks_agent_ratchet_at_both_specs(repo, tmp_path):
    work, base, d = repo
    run = AskRunner({spec_url(P, "php"): {".github/workflows/ci.yml"}, spec_url(T, "php"): {"package.json"}})
    got = gi.gate_inputs(run, {"PATH": "/usr/bin"}, real_git(), work, consumer(tmp_path), base=base, d=d, p=P, t=T,
                         extras="php", g7_files=["tools/use.py"])
    assert [c[0][c[0].index("--with") + 1] for c in run.calls] == [spec_url(P, "php"), spec_url(T, "php")]
    for argv, cwd, stdin in run.calls:
        assert argv[:6] == ("uv", "run", "--isolated", "--no-config", "--no-project", "--with")
        assert argv[7:] == ("python", "-I", "-c", gi.ASK_SCRIPT)
        assert cwd == work
        assert {"src/app.py", "package.json", ".github/workflows/ci.yml", "tests/ci/new_case.py",
                "scripts/audit/a.py", "tests/ci/test_guard_pin.py"} <= set(stdin)
    assert got == frozenset({".github/workflows/ci.yml", "package.json", "requirements-dev.txt", "uv.lock",
                             "scripts/audit/a.py", "tests/ci/test_guard_pin.py", "tests/ci/new_case.py",
                             "tools/use.py"})
    assert "src/app.py" not in got and "README" not in got


@pytest.mark.parametrize("kw", [{"rc": 1, "stdout": b"[]"}, {"stdout": b"not json"}, {"stdout": b'{"a": 1}'},
                                {"stdout": b'["not/asked.txt"]'}])
def test_protected_paths_fails_closed(tmp_path, kw):
    run = AskRunner({}, **kw)
    with pytest.raises(gi.AskError):
        gi.protected_paths(run, {}, tmp_path, spec_url(T, "none"), ["a.txt"])


@pytest.mark.parametrize("paths, expected", [
    (["src/x.py", "scripts/audit/deep/y.py", "guard.lock", "tests/ci/z.py", "scripts/auditx"],
     ["scripts/audit/deep/y.py", "guard.lock", "tests/ci/z.py"]),
    ([], []),
])
def test_touches_matches_inputs_and_globs(paths, expected):
    assert gi.touches(paths, frozenset({"guard.lock"})) == expected


def test_touches_with_custom_globs():
    assert gi.touches(["a/b", "c"], frozenset(), globs=("a/**",)) == ["a/b"]


def test_ask_script_speaks_json_in_and_out(tmp_path):
    """Runs ASK_SCRIPT against a stand-in agent_ratchet package (the real one is never imported by the fleet)."""
    pkg = tmp_path / "agent_ratchet"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("")
    (pkg / "git_guard_io.py").write_text(
        "def is_protected_governance_path(p):\n    return p.startswith('scripts/audit/')\n"
        "def is_package_json_path(p):\n    return p.rsplit('/', 1)[-1] == 'package.json'\n"
        "def package_json_guarded_change(old, new):\n    return old != new\n")
    paths = ["scripts/audit/a.py", "web/package.json", "src/app.py"]
    r = subprocess.run((sys.executable, "-c", gi.ASK_SCRIPT), cwd=tmp_path, input=json.dumps(paths).encode(),
                       capture_output=True, timeout=60)
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout) == ["scripts/audit/a.py", "web/package.json"]
    (pkg / "git_guard_io.py").write_text("def is_protected_governance_path(p):\n    return p == 'guard.lock'\n")
    r = subprocess.run((sys.executable, "-c", gi.ASK_SCRIPT), cwd=tmp_path,
                       input=json.dumps(["guard.lock", "package.json"]).encode(), capture_output=True, timeout=60)
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout) == ["guard.lock"]   # a release before the package.json rule flags none


def test_ask_script_imports_the_core_names():
    assert "from agent_ratchet.git_guard_io import is_protected_governance_path" in gi.ASK_SCRIPT
    assert "package_json_guarded_change" in gi.ASK_SCRIPT
    assert Path(gi.__file__).read_text().count("import agent_ratchet") == 0
