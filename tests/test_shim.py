"""Consumer shim (consumer/guard): resolves guard.lock and execs the pinned agent-ratchet."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess

import pytest
from lock_grammar_cases import LOCK_GRAMMAR_CASES

from agent_ratchet.lock_policy import LockSpec

SHIM = Path(__file__).resolve().parent.parent / "consumer" / "guard"
SHA = "0123456789abcdef0123456789abcdef01234567"
SHA2 = "fedcba9876543210fedcba9876543210fedcba98"
URL = "git+https://github.com/dpopek/agent-ratchet"
BOOTSTRAP = "guard: bootstrap, main has no guard.lock"

FAKE = '#!/bin/sh\nfor a in "$@"; do printf "%s\\n" "$a" >> "$FAKE_OUT"; done\nexit "${FAKE_RC:-0}"\n'


def _git(repo: Path, *args: str) -> str:
    env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull}
    cmd = ["git", "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false", *args]
    return subprocess.run(cmd, cwd=repo, env=env, check=True, capture_output=True, text=True).stdout


def _repo(tmp_path: Path, name: str = "repo") -> Path:
    repo = tmp_path / name
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    return repo


def _fakes(tmp_path: Path) -> Path:
    bindir = tmp_path / "fakebin"
    bindir.mkdir(exist_ok=True)
    for name in ("uvx", "uv"):
        path = bindir / name
        path.write_text(FAKE)
        path.chmod(0o755)
    return bindir


def _run(repo: Path, tmp_path: Path, *args: str, path: str | None = None, rc: int = 0, shell: str = "sh", shim: Path = SHIM):
    out = tmp_path / "argv.txt"
    out.unlink(missing_ok=True)
    env = {"PATH": path or f"{_fakes(tmp_path)}{os.pathsep}{os.environ['PATH']}", "FAKE_OUT": str(out), "FAKE_RC": str(rc), "HOME": str(tmp_path)}
    proc = subprocess.run([shell, str(shim), *args], cwd=repo, env=env, capture_output=True, text=True)
    argv = out.read_text().splitlines() if out.exists() else []
    return proc, argv


def test_shim_passes_pinned_url_and_args(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    (repo / "guard.lock").write_text(SHA + "\n")
    proc, argv = _run(repo, tmp_path, "scan", "--staged", rc=0)
    assert proc.returncode == 0 and proc.stderr == ""
    assert argv == ["--no-config", "--from", f"{URL}@{SHA}", "agent-ratchet", "--expect-sha", SHA, "scan", "--staged"]
    proc, _ = _run(repo, tmp_path, "scan", rc=7)
    assert proc.returncode == 7


@pytest.mark.parametrize("content", [SHA + "\r\n", SHA.upper() + "\n", SHA[:39] + "\n", f"{SHA}\n{SHA}\n", SHA + "\n\n", " " + SHA + "\n", "", "\n", SHA + " \n"])
def test_shim_rejects_malformed_lock(tmp_path: Path, content: str) -> None:
    repo = _repo(tmp_path)
    (repo / "guard.lock").write_bytes(content.encode())
    proc, argv = _run(repo, tmp_path, "scan")
    assert proc.returncode == 3 and proc.stderr.startswith("guard: ") and argv == []


@pytest.mark.parametrize("content", [SHA + "\n", SHA])
def test_shim_accepts_lf_or_no_newline(tmp_path: Path, content: str) -> None:
    repo = _repo(tmp_path)
    (repo / "guard.lock").write_bytes(content.encode())
    proc, argv = _run(repo, tmp_path, "version")
    assert proc.returncode == 0 and argv[5] == SHA


def test_shim_missing_lock_exits_3(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    proc, argv = _run(repo, tmp_path, "scan")
    assert proc.returncode == 3 and "guard.lock" in proc.stderr and argv == []


def test_shim_fails_closed_without_uvx(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    (repo / "guard.lock").write_text(SHA + "\n")
    bindir = tmp_path / "minbin"
    bindir.mkdir()
    for tool in ("git", "sh", "cat", "wc", "tr"):
        found = shutil.which(tool)
        assert found
        (bindir / tool).symlink_to(found)
    proc, argv = _run(repo, tmp_path, "scan", path=str(bindir))
    assert proc.returncode == 3 and "astral.sh/uv" in proc.stderr and argv == []
    proc, argv = _run(repo, tmp_path, "exec", "--", "true", path=str(bindir))
    assert proc.returncode == 3 and "astral.sh/uv" in proc.stderr


def _commit_lock(repo: Path, content: str) -> None:
    (repo / "guard.lock").write_text(content)
    _git(repo, "add", "guard.lock")
    _git(repo, "commit", "-q", "-m", "lock")


def test_shim_lock_from_ref_reads_base_lock(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    _commit_lock(repo, SHA + "\n")
    (repo / "guard.lock").write_text(SHA2 + "\n")  # worktree differs from the base
    proc, argv = _run(repo, tmp_path, "--lock-from", "main", "scan")
    assert proc.returncode == 0 and proc.stderr == ""
    assert argv[:6] == ["--no-config", "--from", f"{URL}@{SHA}", "agent-ratchet", "--expect-sha", SHA] and argv[6:] == ["scan"]


def test_shim_lock_from_ref_bootstrap_falls_back_with_notice(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    (repo / "README").write_text("x\n")
    _git(repo, "add", "README")
    _git(repo, "commit", "-q", "-m", "init")
    (repo / "guard.lock").write_text(SHA2 + "\n")
    proc, argv = _run(repo, tmp_path, "--lock-from", "main", "scan")
    assert proc.returncode == 0 and proc.stderr == BOOTSTRAP + "\n"
    assert argv[2] == f"{URL}@{SHA2}"


def test_shim_runs_from_subdirectory_with_spaces(tmp_path: Path) -> None:
    repo = _repo(tmp_path, "my repo")
    (repo / "guard.lock").write_text(SHA + "\n")
    sub = repo / "a dir" / "deep"
    sub.mkdir(parents=True)
    proc, argv = _run(sub, tmp_path, "scan", "a b")
    assert proc.returncode == 0 and argv[-2:] == ["scan", "a b"]


def test_shim_exec_uses_uv_run_with(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    (repo / "guard.lock").write_text(SHA + "\n")
    proc, argv = _run(repo, tmp_path, "exec", "--", "python", "-m", "pytest", rc=5)
    assert proc.returncode == 5
    assert argv == ["run", "--no-config", "--no-project", "--with", f"{URL}@{SHA}", "--", "python", "-m", "pytest"]
    _commit_lock(repo, SHA2 + "\n")
    _, argv = _run(repo, tmp_path, "exec", "--lock-from", "main", "--", "pytest")
    assert argv[4] == f"{URL}@{SHA2}"


def test_shim_rejects_symlinked_worktree_lock(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    (repo / "real.lock").write_text(SHA + "\n")
    (repo / "guard.lock").symlink_to("real.lock")
    proc, argv = _run(repo, tmp_path, "scan")
    assert proc.returncode == 3 and "regular file" in proc.stderr and argv == []


def test_shim_rejects_non_regular_lock_entry_in_ref(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    (repo / "real.lock").write_text(SHA + "\n")
    (repo / "guard.lock").symlink_to("real.lock")
    _git(repo, "add", "real.lock", "guard.lock")
    _git(repo, "commit", "-q", "-m", "symlink lock")
    (repo / "guard.lock").unlink()
    (repo / "guard.lock").write_text(SHA + "\n")
    proc, argv = _run(repo, tmp_path, "--lock-from", "main", "scan")
    assert proc.returncode == 3 and "regular file" in proc.stderr and argv == []
    assert BOOTSTRAP not in proc.stderr


def test_shim_takes_lock_from_index_not_unstaged_worktree_edit(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    _commit_lock(repo, SHA + "\n")
    (repo / "guard.lock").write_text(SHA2 + "\n")  # unstaged pin edit
    for args in (("scan", "--staged-only"), ("baseline-integrity", "--enforce-policy-isolation")):
        proc, argv = _run(repo, tmp_path, *args)
        assert proc.returncode == 0 and proc.stderr == ""
        assert argv[:6] == ["--no-config", "--from", f"{URL}@{SHA}", "agent-ratchet", "--expect-sha", SHA]
    _, argv = _run(repo, tmp_path, "exec", "--", "pytest")
    assert argv[4] == f"{URL}@{SHA}"


def test_shim_staged_lock_wins_over_head(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    _commit_lock(repo, SHA + "\n")
    (repo / "guard.lock").write_text(SHA2 + "\n")
    _git(repo, "add", "guard.lock")
    (repo / "guard.lock").unlink()  # worktree copy is not needed when the index has the lock
    proc, argv = _run(repo, tmp_path, "scan", "--staged-only")
    assert proc.returncode == 0 and argv[2] == f"{URL}@{SHA2}"


def test_shim_rejects_symlink_lock_in_index(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    (repo / "real.lock").write_text(SHA + "\n")
    (repo / "guard.lock").symlink_to("real.lock")
    _git(repo, "add", "real.lock", "guard.lock")
    (repo / "guard.lock").unlink()
    (repo / "guard.lock").write_text(SHA + "\n")  # regular worktree file must not mask the index entry
    proc, argv = _run(repo, tmp_path, "scan", "--staged-only")
    assert proc.returncode == 3 and "index" in proc.stderr and argv == []


def test_shim_rejects_malformed_index_lock_despite_valid_worktree(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    (repo / "guard.lock").write_text(SHA[:39] + "\n")
    _git(repo, "add", "guard.lock")
    (repo / "guard.lock").write_text(SHA + "\n")
    proc, argv = _run(repo, tmp_path, "scan", "--staged-only")
    assert proc.returncode == 3 and "malformed" in proc.stderr and argv == []


def _place_lock(repo: Path, source: str, content: bytes) -> tuple[str, ...]:
    """Puts ``content`` where ``source`` reads it; returns the shim args selecting that source."""
    if source == "ref":
        (repo / "guard.lock").write_bytes(content)
        _git(repo, "add", "guard.lock")
        _git(repo, "commit", "-q", "-m", "lock")
        (repo / "guard.lock").write_text(SHA2 + "\n")
        return ("--lock-from", "main")
    (repo / "guard.lock").write_bytes(content)
    if source == "index":
        _git(repo, "add", "guard.lock")
        (repo / "guard.lock").write_text(SHA2 + "\n")
    return ()


_SHELLS = ["sh", *(["dash"] if shutil.which("dash") else [])]


@pytest.mark.parametrize(("shell", "source"), [(s, src) for s in _SHELLS for src in ("wt", "index", "ref")])
@pytest.mark.parametrize(("content", "expected"), LOCK_GRAMMAR_CASES, ids=[repr(c) for c, _ in LOCK_GRAMMAR_CASES])
def test_shim_lock_grammar_matches_python(tmp_path: Path, shell: str, source: str, content: bytes, expected: LockSpec | None) -> None:
    repo = _repo(tmp_path)
    lock_args = _place_lock(repo, source, content)
    proc, argv = _run(repo, tmp_path, *lock_args, "scan", shell=shell)
    if expected is None:
        assert proc.returncode == 3 and "guard.lock is malformed" in proc.stderr and argv == [], proc.stderr
        return
    assert proc.returncode == 0 and proc.stderr == "", proc.stderr
    spec = f"{URL}@{expected.sha}" if expected.extras in (None, "none") else f"agent-ratchet[{expected.extras}] @ {URL}@{expected.sha}"
    assert argv == ["--no-config", "--from", spec, "agent-ratchet", "--expect-sha", expected.sha, "scan"]


def test_shim_passes_extra_in_both_paths(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    (repo / "guard.lock").write_text(f"{SHA}\nEXTRAS=php\n")
    spec = f"agent-ratchet[php] @ {URL}@{SHA}"
    proc, argv = _run(repo, tmp_path, "scan", "--staged")
    assert proc.returncode == 0 and proc.stderr == ""
    assert argv == ["--no-config", "--from", spec, "agent-ratchet", "--expect-sha", SHA, "scan", "--staged"]
    proc, argv = _run(repo, tmp_path, "exec", "--", "python", "-m", "pytest")
    assert proc.returncode == 0 and proc.stderr == ""
    assert argv == ["run", "--no-config", "--no-project", "--with", spec, "--", "python", "-m", "pytest"]


@pytest.mark.parametrize("content", [SHA + "\n", SHA, f"{SHA}\nEXTRAS=none\n", f"{SHA}\nEXTRAS=none"])
def test_shim_no_extra_is_byte_identical_argv(tmp_path: Path, content: str) -> None:
    root = SHIM.parent.parent
    if subprocess.run(["git", "rev-parse", "-q", "--verify", "refs/tags/v3.2.0^{commit}"], cwd=root, capture_output=True).returncode != 0:
        pytest.skip("tag v3.2.0 is not available in this clone")
    old = tmp_path / "guard-v3.2.0"
    old.write_bytes(subprocess.run(["git", "show", "v3.2.0:consumer/guard"], cwd=root, check=True, capture_output=True).stdout)
    repo = _repo(tmp_path)
    (repo / "guard.lock").write_text(SHA + "\n")
    for args in (("scan", "--staged", "a b"), ("exec", "--", "pytest", "-q")):
        _, want = _run(repo, tmp_path, *args, shim=old)
        (repo / "guard.lock").write_bytes(content.encode())
        proc, got = _run(repo, tmp_path, *args)
        (repo / "guard.lock").write_text(SHA + "\n")
        assert proc.returncode == 0 and want and got == want


@pytest.mark.integration
def test_shim_extra_real_uv_install(tmp_path: Path) -> None:
    uv = shutil.which("uv")
    if uv is None:
        pytest.skip("uv not found")
    root = SHIM.parent.parent
    clone = tmp_path / "clone"
    subprocess.run(["git", "clone", "-q", "--no-hardlinks", str(root), str(clone)], check=True, capture_output=True)
    sha = _git(clone, "rev-parse", "HEAD").strip()
    venv = tmp_path / "venv"
    subprocess.run([uv, "venv", "-q", "--no-config", "--python", "3.11", str(venv)], check=True, capture_output=True)
    spec = f"agent-ratchet[php] @ git+{clone.as_uri()}@{sha}"
    proc = subprocess.run(
        [uv, "pip", "install", "--no-config", "--dry-run", "--python", str(venv / "bin" / "python"), spec],
        capture_output=True, text=True,
    )
    assert proc.returncode == 0, proc.stderr
    assert "Would install" in proc.stderr and "agent-ratchet" in proc.stderr


def test_shim_rejects_unmerged_index_lock(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    _commit_lock(repo, SHA + "\n")
    _git(repo, "checkout", "-q", "-b", "other")
    _commit_lock(repo, SHA2 + "\n")
    _git(repo, "checkout", "-q", "main")
    _commit_lock(repo, "1" * 40 + "\n")
    merge = subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.com", "merge", "-q", "other"],
        cwd=repo, capture_output=True, text=True,
        env={**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull},
    )
    assert merge.returncode != 0 and _git(repo, "ls-files", "-u", "--", "guard.lock"), merge.stderr
    (repo / "guard.lock").write_text(SHA + "\n")
    proc, argv = _run(repo, tmp_path, "scan", "--staged-only")
    assert proc.returncode == 3 and "index" in proc.stderr and argv == []
