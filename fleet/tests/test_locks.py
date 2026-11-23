from __future__ import annotations

import pytest
from fakes import FakeRunner, Route
from guard_fleet.locks import RunLock, guard_bump_running


def test_run_lock_exclusive_blocks_shared(tmp_path):
    a, b = RunLock(tmp_path / "run.lock"), RunLock(tmp_path / "run.lock")
    assert a.acquire(exclusive=True) and not b.acquire(exclusive=False)
    a.release()
    assert b.acquire(exclusive=False)
    b.release()


def test_run_lock_shared_locks_coexist_but_block_exclusive(tmp_path):
    a, b, c = (RunLock(tmp_path / "s" / "run.lock") for _ in range(3))
    assert a.acquire(exclusive=False) and b.acquire(exclusive=False)
    assert not c.acquire(exclusive=True)
    for lock in (a, b, c):
        lock.release()


def test_run_lock_context_manager_releases(tmp_path):
    with RunLock(tmp_path / "run.lock"):
        assert not RunLock(tmp_path / "run.lock").acquire(exclusive=False)
    other = RunLock(tmp_path / "run.lock")
    assert other.acquire(exclusive=True)
    other.release()


def test_run_lock_context_manager_raises_when_busy(tmp_path):
    held = RunLock(tmp_path / "run.lock")
    assert held.acquire(exclusive=True)
    with pytest.raises(RuntimeError):
        with RunLock(tmp_path / "run.lock"):
            pass
    held.release()


def test_release_without_acquire_is_noop(tmp_path):
    RunLock(tmp_path / "run.lock").release()


@pytest.mark.parametrize("rc,expected", [(0, True), (1, False), (2, True)])
def test_guard_bump_running_fails_closed(tmp_path, rc, expected):
    assert guard_bump_running(FakeRunner([Route(("pgrep",), rc=rc)]), {}, tmp_path) is expected
