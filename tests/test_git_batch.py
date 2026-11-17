"""One `git cat-file --batch` per scan: same bytes, same errors, fewer subprocesses than one-shot `git cat-file`."""

from __future__ import annotations

import contextlib
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import time
from typing import Callable

import pytest

from agent_ratchet import ai_slop_scanner, git_batch
from agent_ratchet.ast_safety import GuardAnalysisError
from agent_ratchet.git_batch import GitBatchReader, _git_cat_bytes_oneshot, active_reader_for, git_batch_session
from agent_ratchet.git_guard_io import git_cat_bytes

sys.path.insert(0, str(Path(__file__).resolve().parent))
from guard_repo_harness import _commit_files, _git, _init_guard_repo, _run_scanner

TWO_MIB = 2 * 2**20


def _new_repo(path: Path) -> Path:
    path.mkdir(parents=True)
    return _init_guard_repo(str(path))


def _outcome(fn: Callable[[], bytes | None]) -> tuple[str, object]:
    try:
        return ("ok", fn())
    except GuardAnalysisError as exc:
        return ("err", str(exc))


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    r = _new_repo(tmp_path / "repo")
    _commit_files(r, "chore: initial", {
        "a.py": "x = 1\n",
        "gone.py": "y = 2\n",
        "old_name.py": "z = 3\n",
        "dir/inner.py": "w = 4\n",
        "latin1.py": b"# caf\xe9\nq = 1\n",
        "big.bin": os.urandom(TWO_MIB),
    }, include_guards=True)
    _git(r, "rm", "-q", "gone.py")
    _git(r, "mv", "old_name.py", "new_name.py")
    os.symlink("a.py", r / "link.py")
    _git(r, "add", "link.py")
    _git(r, "commit", "-q", "-m", "chore: delete, rename, symlink")
    return r


READ_SPECS = (
    "HEAD:a.py", ":a.py", "HEAD:gone.py", "HEAD~1:gone.py", "HEAD:old_name.py", "HEAD~1:old_name.py",
    "HEAD:new_name.py", "HEAD:link.py", ":link.py", "HEAD:latin1.py", "HEAD:big.bin", "HEAD:missing.py",
    ":missing.py", "0000000:a.py", "nosuchref:a.py",
    # Revs with ':' must not share a "missing-safe" memo key: the first resolves, the second does not.
    "HEAD^{/chore: initial}:zz", "HEAD^{/chore: nomatch}:a.py", "HEAD@{0}:zz", "HEAD@{99}:a.py",
)


def test_reads_match_oneshot(repo: Path) -> None:
    cwd = str(repo)
    with GitBatchReader(cwd) as reader:
        for spec in READ_SPECS:
            assert _outcome(lambda: reader.read_spec(spec)) == _outcome(lambda: _git_cat_bytes_oneshot(spec, cwd)), spec
        # Second pass: cache and "missing" memo answer the same way as the first.
        for spec in READ_SPECS:
            assert _outcome(lambda: reader.read_spec(spec)) == _outcome(lambda: _git_cat_bytes_oneshot(spec, cwd)), spec
    assert reader.stats.cache_hits > 0
    assert _git_cat_bytes_oneshot("HEAD:link.py", cwd) == b"a.py"
    assert _outcome(lambda: _git_cat_bytes_oneshot("nosuchref:a.py", cwd))[0] == "err"  # batch says "missing" here


def _write_colliding_blobs(repo: Path) -> str:
    seen: dict[str, bytes] = {}
    for i in range(100_000):
        content = f"ambiguous {i}\n".encode()
        prefix = hashlib.sha1(b"blob %d\0" % len(content) + content).hexdigest()[:4]
        if prefix in seen:
            for data in (seen[prefix], content):
                subprocess.run(["git", "hash-object", "-w", "--stdin"], cwd=repo, input=data, check=True, capture_output=True)
            return prefix
        seen[prefix] = content
    raise AssertionError("no 4-hex prefix collision found")


@pytest.mark.parametrize("kind", ["tree", "ambiguous"])
def test_non_blob_spec_error_identical(repo: Path, kind: str) -> None:
    cwd = str(repo)
    spec = "HEAD:dir" if kind == "tree" else _write_colliding_blobs(repo)
    expected = _outcome(lambda: _git_cat_bytes_oneshot(spec, cwd))
    if kind == "tree":
        assert expected[0] == "err"
    with git_batch_session(cwd) as reader:
        assert _outcome(lambda: git_cat_bytes(spec, cwd)) == expected
        assert _outcome(lambda: reader.read_spec(spec)) == expected
        # The stream stays in sync after the fallback.
        assert reader.read_spec("HEAD:a.py") == b"x = 1\n"


def test_newline_path_bypasses_batch(repo: Path) -> None:
    cwd = str(repo)
    _commit_files(repo, "chore: odd name", {"a\nb.py": "odd = 1\n"})
    with git_batch_session(cwd) as reader:
        assert git_cat_bytes("HEAD:a\nb.py", cwd) == b"odd = 1\n"
        assert reader.read_spec("HEAD:a\nb.py") == b"odd = 1\n"
        assert reader.read_spec("HEAD:a.py") == b"x = 1\n"
        assert git_cat_bytes("HEAD:a.py", cwd) == b"x = 1\n"


def test_killed_batch_process_raises(repo: Path) -> None:
    with GitBatchReader(str(repo)) as reader:
        assert reader.read_spec("HEAD:a.py") == b"x = 1\n"
        reader._proc.kill()
        reader._proc.wait()
        started = time.monotonic()
        with pytest.raises(GuardAnalysisError, match=r"^git cat-file --batch failed for 'HEAD:latin1.py': "):
            reader.read_spec("HEAD:latin1.py")
        assert time.monotonic() - started < 5
        with pytest.raises(GuardAnalysisError, match=r"^git cat-file --batch failed for 'HEAD:new_name.py': "):
            reader.read_spec("HEAD:new_name.py")


def test_truncated_output_raises(repo: Path) -> None:
    with GitBatchReader(str(repo), timeout_s=5.0) as reader:
        assert reader.read_spec("HEAD:a.py") == b"x = 1\n"
        r_fd, w_fd = os.pipe()
        os.write(w_fd, b"0123456789012345678901234567890123456789 blob 100\n" + b"x" * 10)
        os.close(w_fd)
        real_stdout = reader._proc.stdout
        reader._proc.stdout = os.fdopen(r_fd, "rb")
        try:
            with pytest.raises(GuardAnalysisError, match=r"^git cat-file --batch failed for 'HEAD:latin1.py': short read"):
                reader.read_spec("HEAD:latin1.py")
        finally:
            real_stdout.close()


def test_timeout_raises(repo: Path) -> None:
    with GitBatchReader(str(repo), timeout_s=0.5) as reader:
        assert reader.read_spec("HEAD:a.py") == b"x = 1\n"
        r_fd, w_fd = os.pipe()
        real_stdout = reader._proc.stdout
        reader._proc.stdout = os.fdopen(r_fd, "rb")
        try:
            with pytest.raises(GuardAnalysisError, match=r"timed out"):
                reader.read_spec("HEAD:latin1.py")
        finally:
            os.close(w_fd)
            real_stdout.close()


def test_other_cwd_bypasses_session(tmp_path: Path) -> None:
    repo_a = _new_repo(tmp_path / "a")
    _commit_files(repo_a, "chore: a", {"x": "from A\n"})
    repo_b = _new_repo(tmp_path / "b")
    _commit_files(repo_b, "chore: b", {"x": "from B\n"})
    with git_batch_session(str(repo_a)) as reader:
        assert active_reader_for(str(repo_a)) is reader
        assert active_reader_for(str(repo_b)) is None
        assert git_cat_bytes("HEAD:x", cwd=str(repo_b)) == b"from B\n"
        assert git_cat_bytes("HEAD:x", cwd=str(repo_a)) == b"from A\n"
        assert reader.stats.reads == 1
    assert active_reader_for(str(repo_a)) is None
    assert reader._proc is None


def test_unborn_head_uses_reader_head_check(tmp_path: Path) -> None:
    repo = _new_repo(tmp_path / "r")
    with git_batch_session(str(repo)) as reader:
        assert git_cat_bytes("HEAD:x", cwd=str(repo)) is None
        assert reader.head_exists() is False
        assert reader._proc is None


def test_session_is_lazy_outside_git(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    plain = tmp_path / "plain"
    (plain / "src").mkdir(parents=True)
    (plain / "src" / "ok.py").write_text("x = 1\n", encoding="utf-8")
    with git_batch_session(str(plain)) as reader:
        pass
    assert reader._proc is None
    monkeypatch.chdir(plain)
    assert ai_slop_scanner.main(["src/ok.py"]) == 0


def test_nested_sessions_restore_binding(tmp_path: Path) -> None:
    outer_dir, inner_dir = tmp_path / "o", tmp_path / "i"
    outer_dir.mkdir()
    inner_dir.mkdir()
    with git_batch_session(str(outer_dir)) as outer:
        with git_batch_session(str(inner_dir)) as inner:
            assert active_reader_for(str(inner_dir)) is inner
            assert active_reader_for(str(outer_dir)) is None
        assert active_reader_for(str(outer_dir)) is outer
    assert active_reader_for(str(outer_dir)) is None


def test_cache_budget_respected(repo: Path) -> None:
    budget = 2**20
    blob_size = 100 * 1024
    _commit_files(repo, "chore: blobs", {f"blobs/b{i}.bin": bytes([i]) * blob_size for i in range(50)})
    with GitBatchReader(str(repo), cache_budget_bytes=budget) as reader:
        for i in range(50):
            assert reader.read_spec(f"HEAD:blobs/b{i}.bin") == bytes([i]) * blob_size
            assert reader.stats.cached_bytes <= budget
        assert reader.stats.cached_bytes > 0
        hits = reader.stats.cache_hits
        assert reader.read_path("HEAD", "blobs/b49.bin") == bytes([49]) * blob_size
        assert reader.stats.cache_hits == hits + 1
        assert reader.read_spec("HEAD:big.bin") is not None  # 2 MiB > budget // 8: returned, not cached
        assert reader.stats.cached_bytes <= budget
        assert reader.read_path("", "a.py") == b"x = 1\n"


def _scan_cli(repo: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], argv: list[str]) -> tuple[int, str, str]:
    monkeypatch.chdir(repo)
    rc = ai_slop_scanner.main(argv)
    captured = capsys.readouterr()
    return rc, captured.out, captured.err


def test_shallow_clone_missing_base(repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    clone = tmp_path / "shallow"
    subprocess.run(["git", "clone", "-q", "--depth", "1", repo.as_uri(), str(clone)], check=True, capture_output=True)
    cwd = str(clone)
    without = _outcome(lambda: ai_slop_scanner._evaluate_commit_range("HEAD~1..HEAD", cwd=cwd))
    with git_batch_session(cwd):
        with_session = _outcome(lambda: ai_slop_scanner._evaluate_commit_range("HEAD~1..HEAD", cwd=cwd))
    assert with_session == without
    argv = ["--commit-range", "HEAD~1..HEAD"]
    session_cli = _scan_cli(clone, monkeypatch, capsys, argv)
    monkeypatch.setattr(ai_slop_scanner, "git_batch_session", lambda cwd=None: contextlib.nullcontext())
    oneshot_cli = _scan_cli(clone, monkeypatch, capsys, argv)
    assert session_cli == oneshot_cli
    assert session_cli[0] == 2
    assert _run_scanner(clone, *argv).returncode == 2


CHANGED_FILES = 40


def _count_popen(monkeypatch: pytest.MonkeyPatch, fn: Callable[[], object]) -> tuple[int, object]:
    calls: list[object] = []
    original = subprocess.Popen.__init__

    def counting_init(self: subprocess.Popen, *args: object, **kwargs: object) -> None:
        calls.append(args[0] if args else kwargs.get("args"))
        original(self, *args, **kwargs)

    monkeypatch.setattr(subprocess.Popen, "__init__", counting_init)
    try:
        result = fn()
    finally:
        monkeypatch.setattr(subprocess.Popen, "__init__", original)
    return len(calls), result


def test_subprocess_count_reduced(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = _new_repo(tmp_path / "r")
    base = _commit_files(repo, "chore: base", {f"src/domain/m{i}.py": f"def f{i}(a):\n    return a + {i}\n" for i in range(CHANGED_FILES)}, include_guards=True)
    head = _commit_files(repo, "feat: change", {f"src/domain/m{i}.py": f"def f{i}(a):\n    return a * {i}\n" for i in range(CHANGED_FILES)})
    cwd = str(repo)
    range_spec = f"{base}..{head}"
    without, plain_result = _count_popen(monkeypatch, lambda: ai_slop_scanner._evaluate_commit_range(range_spec, cwd=cwd))

    def with_session() -> object:
        with git_batch_session(cwd):
            return ai_slop_scanner._evaluate_commit_range(range_spec, cwd=cwd)

    with_count, session_result = _count_popen(monkeypatch, with_session)
    print(f"\nsubprocess count for {CHANGED_FILES} changed files: without session={without}, with session={with_count}")
    assert session_result == plain_result
    assert without >= 5 * with_count, (without, with_count)


def test_interrupt_mid_read_resets_stream(repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    real_read = os.read
    calls = {"n": 0}

    def interrupting_read(fd: int, n: int) -> bytes:
        calls["n"] += 1
        if calls["n"] == 2:
            raise KeyboardInterrupt
        return real_read(fd, n)

    with GitBatchReader(str(repo)) as reader:
        assert reader.read_spec("HEAD:a.py") == b"x = 1\n"
        monkeypatch.setattr(git_batch.os, "read", interrupting_read)
        calls["n"] = 0
        with pytest.raises(KeyboardInterrupt):
            reader.read_spec("HEAD:big.bin")
        monkeypatch.setattr(git_batch.os, "read", real_read)
        assert reader._proc is None and not reader._buf
        assert reader.read_spec("HEAD:latin1.py") == b"# caf\xe9\nq = 1\n"
        assert reader.read_spec("HEAD:big.bin") == _git_cat_bytes_oneshot("HEAD:big.bin", str(repo))


def test_deleted_cwd_session_falls_back_to_oneshot(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = _new_repo(tmp_path / "r")
    _commit_files(repo, "chore: r", {"x": "from R\n"})
    gone = tmp_path / "gone"
    gone.mkdir()
    monkeypatch.chdir(gone)
    gone.rmdir()
    with git_batch_session() as reader:
        assert reader is None
        assert active_reader_for(None) is None
        assert git_cat_bytes("HEAD:x", cwd=str(repo)) == b"from R\n"


def test_deleted_cwd_inside_session_bypasses_reader(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    work = tmp_path / "w"
    work.mkdir()
    monkeypatch.chdir(work)
    with git_batch_session() as reader:
        assert reader is not None
        work.rmdir()
        assert active_reader_for(None) is None
