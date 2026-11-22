import os
import signal
import sys
import time

import pytest

from guard_fleet import proc
from guard_fleet.proc import Result, low_priority_prefix
from fakes import FakeClock, FakeRunner, Route, make_deps


def test_run_stdin_is_devnull_and_timeout_kills_group(tmp_path):
    r = proc.run([sys.executable, "-c", "import sys; print(sys.stdin.read() == '')"], cwd=tmp_path, env=os.environ, timeout=10)
    assert r.rc == 0 and r.stdout.strip() == b"True"
    r = proc.run([sys.executable, "-c", "import time; time.sleep(30)"], cwd=tmp_path, env=os.environ, timeout=0.5)
    assert r.timed_out and r.rc == 124


def _gone(pid: int, wait: float = 5.0) -> bool:
    deadline = time.monotonic() + wait
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        time.sleep(0.05)
    return False


def test_timeout_kills_grandchild_in_same_group(tmp_path):
    r = proc.run(["sh", "-c", "sleep 60 & echo $!; wait"], cwd=tmp_path, env=os.environ, timeout=0.5)
    pid = int(r.stdout.split()[0])
    try:
        assert r.timed_out and r.rc == 124
        assert _gone(pid), "grandchild survived the group kill"
    finally:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def test_timeout_does_not_hang_on_escaped_grandchild(tmp_path):
    code = ("import os, time\n"
            "pid = os.fork()\n"
            "if pid == 0:\n"
            "    os.setsid(); time.sleep(60); os._exit(0)\n"
            "print(pid, flush=True); time.sleep(60)\n")
    start = time.monotonic()
    r = proc.run([sys.executable, "-c", code], cwd=tmp_path, env=os.environ, timeout=0.5)
    elapsed = time.monotonic() - start
    pids = r.stdout.split()
    try:
        assert r.timed_out and r.rc == 124
        assert elapsed < 0.5 + proc.POST_KILL_DRAIN + 3
    finally:
        if pids:
            try:
                os.kill(int(pids[0]), signal.SIGKILL)
            except ProcessLookupError:
                pass


def test_run_passes_input_and_captures_stderr(tmp_path):
    code = "import sys; d = sys.stdin.buffer.read(); sys.stdout.buffer.write(d); sys.stderr.write('e'); sys.exit(3)"
    r = proc.run([sys.executable, "-c", code], cwd=tmp_path, env=os.environ, timeout=10, input=b"abc")
    assert (r.rc, r.stdout, r.stderr, r.timed_out) == (3, b"abc", b"e", False)


def test_run_missing_executable_is_127(tmp_path):
    assert proc.run(["guard-fleet-no-such-exe"], cwd=tmp_path, env=os.environ, timeout=5).rc == 127


def test_run_log_is_appended_with_mode_600(tmp_path):
    log = tmp_path / "logs" / "g.log"
    proc.run([sys.executable, "-c", "print('hi')"], cwd=tmp_path, env=os.environ, timeout=10, log=log)
    text = log.read_text()
    assert text.startswith("$ ") and "hi" in text and "rc=0" in text
    assert (log.stat().st_mode & 0o777) == 0o600
    proc.run([sys.executable, "-c", "print('again')"], cwd=tmp_path, env=os.environ, timeout=10, log=log)
    assert log.read_text().count("rc=0") == 2


def test_result_text_replaces_invalid_utf8():
    r = Result(("x",), 0, b"a\xffb", b"", False)
    assert r.text == "a�b"


def test_low_priority_prefix():
    assert low_priority_prefix("darwin", lambda n: "/usr/sbin/" + n) == ("taskpolicy", "-c", "utility", "-d", "utility", "nice", "-n", "15")
    assert low_priority_prefix("linux", lambda n: "/usr/bin/" + n if n == "nice" else None) == ("nice", "-n", "15")
    assert low_priority_prefix("linux", lambda n: None) == ()


def test_fake_runner_rejects_unrouted_argv(tmp_path):
    with pytest.raises(AssertionError):
        FakeRunner([])(["gh", "api", "user"], cwd=tmp_path, env={}, timeout=1)


def test_fake_runner_routes_and_records(tmp_path):
    runner = FakeRunner([Route(("gh", "api"), stdout=b"{}"), Route(lambda a: a[0] == "uv", rc=7)])
    r = runner(["gh", "api", "user"], cwd=tmp_path, env={"A": "1"}, timeout=1)
    assert r.stdout == b"{}" and r.argv == ("gh", "api", "user")
    assert runner(["uv", "x"], cwd=tmp_path, env={}, timeout=1).rc == 7
    assert runner.calls[0] == (("gh", "api", "user"), tmp_path, {"A": "1"})


def test_fake_runner_strips_low_priority_prefix_and_effect(tmp_path):
    prefix = ("nice", "-n", "15")
    seen = []

    def effect(argv, cwd, env):
        seen.append(argv)
        return Result(argv, 9, b"", b"", False)

    runner = FakeRunner([Route(("uv", "run"), effect=effect)])
    assert runner([*prefix, "uv", "run", "t"], cwd=tmp_path, env={}, timeout=1).rc == 9
    assert seen == [("uv", "run", "t")]


def test_fake_runner_real_git(tmp_path):
    r = FakeRunner([])(["git", "--version"], cwd=tmp_path, env=os.environ, timeout=10)
    assert r.rc == 0 and r.stdout.startswith(b"git version")


def test_fake_clock_and_make_deps(tmp_path):
    c = FakeClock()
    c.advance(5)
    assert (c.monotonic(), c.wall()) == (1005.0, 1_700_000_005.0)
    c.advance(10, wall_only=True)
    assert (c.monotonic(), c.wall()) == (1005.0, 1_700_000_015.0)
    d = make_deps(tmp_path, environ={"HOME": str(tmp_path)})
    assert d.dirs.consumers_toml == tmp_path / ".config/guard-fleet/consumers.toml"
    assert d.environ == {"HOME": str(tmp_path)}
    d.sleep(3)
    assert d.clock.monotonic() == 1003.0
