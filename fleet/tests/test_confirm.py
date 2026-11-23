"""Touch ID confirmation: reason text, helper compilation/exit mapping, ask()."""

from __future__ import annotations

import io
from pathlib import Path

import pytest

from fakes import FakeConfirm, make_deps
from guard_fleet import confirm
from guard_fleet.confirm import ask, reason_simple, reason_text, touch_id
from guard_fleet.exits import Cancelled, NoHelper
from guard_fleet.proc import Result


def test_reason_text_limits_and_agent_suffix():
    r = reason_text("land", "v4.4.1", "c305de7" + "0" * 33,
                    {1: ["alpha", "beta", "gamma", "delta"], 2: ["epsilon", "zeta"]}, markers=False)
    assert r == "land v4.4.1 (c305de7): ring 1 alpha, beta, gamma, delta; ring 2 epsilon, zeta"
    long = reason_text("land", "v4.4.1", "c" * 40, {1: [f"c{i}" for i in range(60)]}, markers=True)
    assert len(long) <= 150 and long.endswith(" · from agent shell")
    assert "…" in long


def test_reason_text_skips_empty_rings_and_takes_object_text():
    r = reason_text("land", "v4.4.1", "a" * 40, {1: [], 2: ["alpha"]}, markers=False)
    assert r == "land v4.4.1 (aaaaaaa): ring 2 alpha"


def test_reason_simple_truncates_body_but_never_the_suffix():
    assert reason_simple("cleanup 3 items", markers=False) == "cleanup 3 items"
    assert reason_simple("cleanup 3 items", markers=True) == "cleanup 3 items" + confirm.AGENT_SUFFIX
    out = reason_simple("x" * 400, markers=False)
    assert len(out) == confirm.REASON_MAX and out.endswith("…")
    out = reason_simple("x" * 400, markers=True)
    assert len(out) == confirm.REASON_MAX and out.endswith("…" + confirm.AGENT_SUFFIX)


def test_no_swiftc_or_not_macos_is_no_helper(tmp_path):
    r = touch_id("x", platform="linux")
    assert r.status == "no_helper" and "Xcode Command Line Tools" in r.detail
    assert touch_id("x", platform="darwin", swiftc=tmp_path / "missing").status == "no_helper"


FAKE_SWIFTC = Path(__file__)  # any existing file: the runner below never executes it


class SwiftRunner:
    """Stands in for proc.run: fakes the compile step and the helper run."""

    def __init__(self, rc: int, *, compile_rc: int = 0, timed_out: bool = False) -> None:
        self.rc, self.compile_rc, self.timed_out = rc, compile_rc, timed_out
        self.calls: list[tuple[tuple[str, ...], Path, dict, float, bytes | None]] = []
        self.dirs: list[Path] = []

    def __call__(self, argv, *, cwd, env, timeout, input=None, log=None) -> Result:
        args = tuple(argv)
        self.calls.append((args, cwd, dict(env), timeout, input))
        self.dirs.append(cwd)
        assert cwd.is_dir()
        if args[0] == str(FAKE_SWIFTC):
            assert (cwd / "confirm.swift").is_file()
            if self.compile_rc == 0:
                (cwd / "confirm").write_bytes(b"")
                return Result(args, 0, b"", b"", False)
            return Result(args, self.compile_rc, b"", b"warn\nerror: boom\n", False)
        if self.timed_out:
            return Result(args, 124, b"", b"", True)
        return Result(args, self.rc, b"", b"", False)


@pytest.fixture
def fake_swift_runner():
    return SwiftRunner


@pytest.mark.parametrize("rc,status", [(0, "approved"), (4, "cancelled"), (1, "cancelled"), (5, "no_helper")])
def test_helper_exit_codes(fake_swift_runner, rc, status):
    runner = fake_swift_runner(rc)
    assert touch_id("why", platform="darwin", swiftc=FAKE_SWIFTC, run=runner).status == status
    compile_call, helper_call = runner.calls
    d = runner.dirs[0]
    assert compile_call[0] == (str(FAKE_SWIFTC), "-O", "-o", str(d / "confirm"), str(d / "confirm.swift"))
    assert compile_call[3] == 300
    assert helper_call[0] == (str(d / "confirm"), "why")
    assert helper_call[3] == confirm.TIMEOUT_S
    assert not d.exists()


def test_compile_failure_is_no_helper_with_last_line(fake_swift_runner):
    runner = fake_swift_runner(0, compile_rc=1)
    r = touch_id("x", platform="darwin", swiftc=FAKE_SWIFTC, run=runner)
    assert r.status == "no_helper" and r.detail == "error: boom"
    assert len(runner.calls) == 1 and not runner.dirs[0].exists()


def test_helper_timeout_is_timeout_and_temp_dir_removed(fake_swift_runner):
    runner = fake_swift_runner(0, timed_out=True)
    r = touch_id("x", platform="darwin", swiftc=FAKE_SWIFTC, run=runner)
    assert r.status == "timeout"
    assert len(runner.calls) == 2
    assert not runner.dirs[0].exists()


def test_ask_prints_table_before_dialog_and_maps_exits(tmp_path):
    out = io.StringIO()
    seen: list[str] = []

    def dialog(reason: str):
        seen.append(out.getvalue())
        return FakeConfirm(["approved"])(reason)

    deps = make_deps(tmp_path, confirm=dialog)
    deps.out = out
    assert ask(deps, "TABLE\n", "why") is None
    assert seen == ["TABLE\n"]

    for status, exc in (("cancelled", Cancelled), ("timeout", Cancelled), ("no_helper", NoHelper)):
        fake = FakeConfirm([status])
        deps = make_deps(tmp_path, confirm=fake)
        with pytest.raises(exc):
            ask(deps, "T", "why")
        assert fake.reasons == ["why"]

    deps = make_deps(tmp_path, confirm=FakeConfirm(["no_helper"]))
    with pytest.raises(NoHelper, match="detail-no_helper"):
        ask(deps, "T", "why")


def test_fake_confirm_returns_in_order_and_records():
    f = FakeConfirm(["approved", "cancelled"])
    assert f("a").status == "approved" and f("b").status == "cancelled"
    assert f.reasons == ["a", "b"]


def test_default_deps_wires_touch_id(monkeypatch):
    from guard_fleet.deps import ConfirmResult, default_deps
    monkeypatch.setattr(confirm, "touch_id", lambda reason: ConfirmResult("approved", f"got {reason}"))
    assert default_deps().confirm("x") == ConfirmResult("approved", "got x")
