"""Differential acceptance tool: identical/different outputs, normalisation, cleanup and isolation rules."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import sys

import pytest

TOOL = Path(__file__).resolve().parent.parent / "tools" / "differential_findings.py"
_spec = importlib.util.spec_from_file_location("differential_findings", TOOL)
assert _spec and _spec.loader
diff_tool = importlib.util.module_from_spec(_spec)
sys.modules["differential_findings"] = diff_tool
_spec.loader.exec_module(diff_tool)

STUB = """\
import os, sys
print("cwd=" + os.getcwd())
print("args=" + " ".join(sys.argv[1:]))
print("prog=" + sys.argv[0], file=sys.stderr)
sys.exit(int(os.environ.get("STUB_RC", "0")))
"""


def _git(cwd: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=True).stdout.strip()


@pytest.fixture
def consumer(tmp_path: Path) -> tuple[Path, str]:
    repo = tmp_path / "consumer"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.email", "t@example.invalid")
    _git(repo, "config", "user.name", "t")
    (repo / "a.txt").write_text("one\n")
    _git(repo, "add", "a.txt")
    _git(repo, "commit", "-q", "-m", "one")
    (repo / "a.txt").write_text("two\n")
    _git(repo, "commit", "-q", "-am", "two")
    return repo, _git(repo, "rev-parse", "HEAD")


def _run(consumer_repo: Path, sha: str, out: Path, *extra: str, tmpdir: Path | None = None, env_rc: str | None = None):
    import os

    env = dict(os.environ)
    if tmpdir is not None:
        env["TMPDIR"] = str(tmpdir)
    if env_rc is not None:
        env["STUB_RC"] = env_rc
    argv = [sys.executable, str(TOOL), "--consumer", str(consumer_repo), "--legacy-ref", sha, "--guard-sha", sha, "--commits", "1", "--out", str(out), *extra]
    return subprocess.run(argv, capture_output=True, text=True, env=env)


def _stub_cmd(tmp_path: Path, name: str, body: str = STUB) -> str:
    path = tmp_path / name
    path.write_text(body)
    return f"{sys.executable} {path}"


def test_identical_outputs_exit_0(consumer, tmp_path):
    repo, sha = consumer
    legacy = _stub_cmd(tmp_path, "legacy_stub.py")
    new = _stub_cmd(tmp_path, "new_stub.py")
    out = tmp_path / "out"
    proc = _run(repo, sha, out, "--legacy-cmd", legacy, "--new-cmd", new)
    assert proc.returncode == 0, proc.stderr
    assert not list(out.glob("*.diff"))
    assert (out / "summary.txt").is_file()


def test_any_difference_exit_1_and_writes_diff(consumer, tmp_path):
    repo, sha = consumer
    legacy = _stub_cmd(tmp_path, "legacy_stub.py")
    new = _stub_cmd(tmp_path, "new_stub.py", STUB.replace('print("args="', 'print("ARGS="'))
    out = tmp_path / "out"
    proc = _run(repo, sha, out, "--legacy-cmd", legacy, "--new-cmd", new)
    assert proc.returncode == 1
    diffs = sorted(p.name for p in out.glob("*.diff"))
    assert diffs == ["baseline-isolation.diff", "baseline-require-base-ref.diff", "scan-commit-range.diff", "scan-staged-only.diff"]
    assert "-args=" in (out / "scan-staged-only.diff").read_text()


def test_out_inside_git_repo_refused(consumer, tmp_path):
    repo, sha = consumer
    stub = _stub_cmd(tmp_path, "s.py")
    out = repo / "nested" / "out"
    proc = _run(repo, sha, out, "--legacy-cmd", stub, "--new-cmd", stub)
    assert proc.returncode == 2
    assert not out.exists()


def test_extra_scan_args_adds_cases(consumer, tmp_path):
    repo, sha = consumer
    stub = _stub_cmd(tmp_path, "s.py")
    out = tmp_path / "out"
    proc = _run(repo, sha, out, "--legacy-cmd", stub, "--new-cmd", stub, "--extra-scan-args", "src test")
    assert proc.returncode == 0, proc.stderr
    assert "scan-extra-1" in (out / "summary.txt").read_text()


def test_case_error_is_a_difference_even_when_both_sides_fail(consumer, tmp_path):
    repo, sha = consumer
    out = tmp_path / "out"
    missing = f"{tmp_path}/does-not-exist-binary"
    proc = _run(repo, sha, out, "--legacy-cmd", missing, "--new-cmd", missing)
    assert proc.returncode == 1
    assert "ERROR" in (out / "scan-staged-only.diff").read_text()


def test_missing_default_legacy_script_is_a_difference(consumer, tmp_path):
    repo, sha = consumer
    out = tmp_path / "out"
    new = _stub_cmd(tmp_path, "new_stub.py")
    proc = _run(repo, sha, out, "--new-cmd", new)
    assert proc.returncode == 1
    assert "scripts/audit/ai_slop_scanner.py" in (out / "scan-staged-only.diff").read_text()


def test_timeout_is_a_difference(consumer, tmp_path):
    repo, sha = consumer
    slow = _stub_cmd(tmp_path, "slow.py", "import time\ntime.sleep(30)\n")
    fast = _stub_cmd(tmp_path, "fast.py", "pass\n")
    out = tmp_path / "out"
    proc = _run(repo, sha, out, "--legacy-cmd", slow, "--new-cmd", fast, "--timeout", "1")
    assert proc.returncode == 1
    assert "timed out" in (out / "scan-staged-only.diff").read_text()


def test_temp_clone_removed_and_source_repo_untouched(consumer, tmp_path):
    repo, sha = consumer
    stub = _stub_cmd(tmp_path, "s.py")
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    before = sorted(str(p.relative_to(repo)) for p in repo.rglob("*"))
    proc = _run(repo, sha, tmp_path / "out", "--legacy-cmd", stub, "--new-cmd", stub, tmpdir=scratch)
    assert proc.returncode == 0, proc.stderr
    assert list(scratch.iterdir()) == []
    assert sorted(str(p.relative_to(repo)) for p in repo.rglob("*")) == before
    assert not (repo / ".git" / "worktrees").exists()
    assert _git(repo, "worktree", "list").count("\n") == 0


def test_temp_clone_removed_on_failure(consumer, tmp_path):
    repo, _ = consumer
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    stub = _stub_cmd(tmp_path, "s.py")
    proc = _run(repo, "0" * 40, tmp_path / "out", "--legacy-cmd", stub, "--new-cmd", stub, tmpdir=scratch)
    assert proc.returncode == 2
    assert list(scratch.iterdir()) == []


def test_normalise_clone_path_to_root():
    text = "error in /private/var/folders/x/clone/src/a.py:3\n"
    assert diff_tool.normalise(text, Path("/private/var/folders/x/clone")) == "error in <ROOT>/src/a.py:3\n"


def test_normalise_other_temp_paths():
    out = diff_tool.normalise("wrote /tmp/tmpabc123/x.json and /var/folders/zz/T/y.txt\n", Path("/nowhere"))
    assert out == "wrote <TMP> and <TMP>\n"


def test_normalise_program_names():
    text = "usage: ai_slop_scanner.py x\nusage: test_baseline_integrity.py y\nusage: guard-core scan z\n"
    assert diff_tool.normalise(text, Path("/nowhere")) == "usage: <PROG> x\nusage: <PROG> y\nusage: <PROG> scan z\n"


def test_normalise_leaves_everything_else_alone():
    text = "Line 12: finding  RULE-1  (score 0.5)\n  indented\n"
    assert diff_tool.normalise(text, Path("/nowhere")) == text
