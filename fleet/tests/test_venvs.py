import dataclasses
import stat
from pathlib import Path

import pytest

from fakes import Route
from guard_fleet import proc
from guard_fleet.config import FleetConfig
from guard_fleet.exits import FleetExit, UsageError
from guard_fleet.gh import GhError
from guard_fleet.locks import RunLock
from guard_fleet.venvs import VenvRow, drifted, refresh, report, run_venvs
from guard_fleet.plan import _clients
from repos import _git, commit_files, make_clone, push_all
from test_plan import build_env

OLD = "e" * 40
_GIT_WRITES = {"fetch", "pull", "checkout", "reset", "commit", "update-ref", "push", "merge", "rebase", "clean"}


class VenvEnv:
    """alpha: a pin line and guard.lock at HEAD naming the same sha, one venv at OLD, origin one commit ahead."""

    def __init__(self, tmp_path, home, **kw):
        env = build_env(tmp_path, home, **kw)
        self.deps, base_cfg = env
        self.env = env
        self.clone = env.clones["alpha"]
        self.lock_sha = env.shas["v4.0.0"]
        self.spec = f"agent-ratchet[php] @ git+https://github.com/dpopek/agent-ratchet@{self.lock_sha}"
        commit_files(self.clone, "pin", {"requirements-dev.txt": f"pytest\n{self.spec}\n",
                                         "guard.lock": f"{self.lock_sha}\nEXTRAS=php\n"})
        push_all(self.clone)
        work = make_clone(env.gh_bares["owner/alpha"], tmp_path / "adv")
        commit_files(work, "advance", {"later.txt": "1\n"})
        push_all(work)
        self.venv = self.make_venv(tmp_path / "alpha-venv", OLD)
        alpha = dataclasses.replace(base_cfg.consumers[0], pin_kind="req", pin_file="requirements-dev.txt",
                                    venvs=(self.venv,))
        self.cfg = FleetConfig(base_cfg.worktree_root, (alpha, base_cfg.consumers[1]))
        self.pgrep_rc = 1
        self.install_rc = 0
        self.install_effective = True
        self.deps.run.routes += [
            Route(match=lambda a: a[1:2] == ("-I",),
                  effect=lambda a, cwd, e: proc.run(a, cwd=cwd, env=e, timeout=30)),
            Route(match=("pgrep",), effect=self._pgrep),
            Route(match=("uv", "pip", "install"), effect=self._install),
        ]
        self.git, self.gh = _clients(self.deps)
        self.status_before = self.checkout_status()
        self.refs_before = _git(self.clone, "for-each-ref")

    @staticmethod
    def make_venv(root: Path, commit: str | None) -> Path:
        venv = root
        (venv / "bin").mkdir(parents=True)
        py = venv / "bin" / "python"
        py.write_text('#!/bin/sh\ncat "$(dirname "$0")/../commit" 2>/dev/null\nexit 0\n')
        py.chmod(py.stat().st_mode | stat.S_IXUSR)
        if commit:
            (venv / "commit").write_text(commit + "\n")
        return venv

    def _pgrep(self, argv, cwd, env):
        return proc.Result(argv, self.pgrep_rc, b"", b"", False)

    def _install(self, argv, cwd, env):
        if self.install_effective and self.install_rc == 0:
            (self.venv / "commit").write_text(argv[-1].rsplit("@", 1)[1] + "\n")
        return proc.Result(argv, self.install_rc, b"", b"boom" if self.install_rc else b"", False)

    @property
    def args(self):
        return (self.deps, self.git, self.gh, self.cfg)

    def run_args(self):
        return (self.deps, self.cfg)

    def call(self, *prefix):
        found = [c for c in self.deps.run.calls if c[0][: len(prefix)] == prefix]
        assert len(found) == 1, found
        return found[0][0]

    def calls(self, *prefix):
        return [c for c in self.deps.run.calls if c[0][: len(prefix)] == prefix]

    def checkout_status(self):
        return _git(self.clone, "status", "--porcelain")

    def git_writes_in_checkout(self):
        root = str(self.clone)
        return [c for c in self.deps.run.calls
                if c[0][:1] == ("git",) and str(c[1]).startswith(root) and _GIT_WRITES & set(c[0])]


@pytest.fixture
def venv_env(tmp_path, fleet_home):
    return VenvEnv(tmp_path, fleet_home)


def only_row(rows):
    assert len(rows) == 1
    return rows[0]


def test_report_shows_drift_and_behind_count(venv_env):
    row = only_row(report(*venv_env.args, only=()))
    assert isinstance(row, VenvRow)
    assert (row.short, row.venv, row.installed, row.lock_sha) == ("alpha", venv_env.venv, OLD, venv_env.lock_sha)
    assert row.spec == venv_env.spec
    assert row.state == "drift" and row.behind == 1
    assert "behind origin by 1; pull, then rerun" in row.note
    assert drifted([row])


def test_report_ok_when_installed_matches_the_lock_and_checkout_is_current(venv_env):
    (venv_env.venv / "commit").write_text(venv_env.lock_sha + "\n")
    _git(venv_env.clone, "pull", "-q", "--ff-only")
    row = only_row(report(*venv_env.args, only=()))
    assert row.state == "ok" and row.behind == 0 and row.note == ""
    assert not drifted([row])


def test_report_only_lists_consumers_with_venvs_and_honours_only(venv_env):
    assert [r.short for r in report(*venv_env.args, only=())] == ["alpha"]
    assert [r.short for r in report(*venv_env.args, only=("alpha",))] == ["alpha"]
    assert report(*venv_env.args, only=("beta",)) == []


def test_unknown_short_is_a_usage_error_before_any_lock_or_network_work(venv_env):
    with pytest.raises(UsageError):
        report(*venv_env.args, only=("nope",))
    with pytest.raises(UsageError):
        refresh(*venv_env.args, only=("nope",))
    with pytest.raises(UsageError):
        run_venvs(*venv_env.run_args(), refresh=False, only=("nope",))
    assert venv_env.deps.run.calls == []


def test_behind_is_unknown_with_a_note_when_gh_fails(tmp_path, fleet_home):
    env = VenvEnv(tmp_path, fleet_home, mode="401")
    row = only_row(report(*env.args, only=()))
    assert row.behind is None and "behind origin unknown: " in row.note
    assert row.state == "drift"


def test_behind_is_unknown_when_ls_remote_fails(venv_env):
    gitconfig = Path(venv_env.deps.environ["HOME"]) / ".gitconfig"
    kept = [ln for ln in gitconfig.read_text().splitlines() if "insteadOf" not in ln and not ln.startswith('[url "')]
    gitconfig.write_text("\n".join(kept) + '\n[url "file:///nonexistent/alpha.git"]\n'
                         "\tinsteadOf = https://github.com/owner/alpha\n")
    row = only_row(report(*venv_env.args, only=()))
    assert row.behind is None and "behind origin unknown: " in row.note
    assert row.state == "drift"


def test_missing_when_the_interpreter_or_the_checkout_is_absent(venv_env, tmp_path):
    (venv_env.venv / "bin" / "python").unlink()
    row = only_row(report(*venv_env.args, only=()))
    assert row.state == "missing" and row.installed is None
    gone = dataclasses.replace(venv_env.cfg.consumers[0], dir=tmp_path / "no-such-checkout")
    row = only_row(report(venv_env.deps, venv_env.git, venv_env.gh, FleetConfig(venv_env.cfg.worktree_root, (gone,)),
                          only=()))
    assert row.state == "missing" and row.behind is None
    assert not drifted([row])


def test_pin_and_lock_disagree_is_reported_and_skipped(venv_env):
    commit_files(venv_env.clone, "lock moves", {"guard.lock": "9" * 40 + "\n"})
    rows = report(*venv_env.args, only=())
    assert only_row(rows).state == "disagree" and "pin and lock disagree at HEAD" in rows[0].note
    assert drifted(rows)
    rows = refresh(*venv_env.args, only=())
    assert only_row(rows).state == "disagree"
    assert venv_env.calls("uv") == [] and venv_env.calls("pgrep") == []


def test_no_lock_at_head_is_disagree(venv_env):
    commit_files(venv_env.clone, "drop lock", {"guard.lock": None})
    row = only_row(report(*venv_env.args, only=()))
    assert row.state == "disagree" and "no guard.lock at HEAD" in row.note and row.lock_sha is None


def test_refresh_installs_head_spec_with_extras_and_verifies(venv_env):
    rows = refresh(*venv_env.args, only=())
    argv = venv_env.call("uv", "pip", "install")
    assert argv == ("uv", "pip", "install", "--python", f"{venv_env.venv}/bin/python", "--no-config", venv_env.spec)
    assert argv[-1] == f"agent-ratchet[php] @ git+https://github.com/dpopek/agent-ratchet@{venv_env.lock_sha}"
    row = only_row(rows)
    assert row.state == "refreshed" and row.installed == venv_env.lock_sha
    cwd, env = venv_env.calls("uv", "pip", "install")[0][1:]
    assert cwd == venv_env.venv and not str(cwd).startswith(str(venv_env.clone))
    assert "VIRTUAL_ENV" not in env
    assert venv_env.calls("pgrep")[0][0] == ("pgrep", "-f", f"{venv_env.venv}/bin/")


def test_refresh_uses_the_low_priority_prefix(venv_env, monkeypatch):
    seen = []
    real_run = venv_env.deps.run

    def spy(argv, **kw):
        seen.append(tuple(argv))
        return real_run(argv, **kw)

    spy.routes, spy.calls = real_run.routes, real_run.calls
    prefix = proc.low_priority_prefix()
    venv_env.deps = dataclasses.replace(venv_env.deps, run=spy)
    venv_env.git, venv_env.gh = _clients(venv_env.deps)
    refresh(venv_env.deps, venv_env.git, venv_env.gh, venv_env.cfg, only=())
    install = next(a for a in seen if "install" in a and "uv" in a)
    assert install[: len(prefix)] == prefix and install[len(prefix):][:3] == ("uv", "pip", "install")


def test_refresh_leaves_ok_venvs_alone(venv_env):
    (venv_env.venv / "commit").write_text(venv_env.lock_sha + "\n")
    row = only_row(refresh(*venv_env.args, only=()))
    assert row.state == "ok"
    assert venv_env.calls("uv") == [] and venv_env.calls("pgrep") == []


def test_refresh_skips_venv_in_use(venv_env):
    venv_env.pgrep_rc = 0
    row = only_row(refresh(*venv_env.args, only=()))
    assert row.state == "in-use" and row.installed == OLD
    assert venv_env.calls("uv") == []


def test_refresh_treats_an_unusable_pgrep_as_in_use(venv_env):
    venv_env.pgrep_rc = 2
    assert only_row(refresh(*venv_env.args, only=())).state == "in-use"
    assert venv_env.calls("uv") == []


def test_refresh_reports_failed_when_the_install_errors(venv_env):
    venv_env.install_rc = 1
    row = only_row(refresh(*venv_env.args, only=()))
    assert row.state == "failed" and "boom" in row.note


def test_refresh_reports_failed_when_the_commit_does_not_move(venv_env):
    venv_env.install_effective = False
    row = only_row(refresh(*venv_env.args, only=()))
    assert row.state == "failed" and row.installed == OLD and "lock" in row.note


def test_refresh_without_a_pin_spec_fails_the_row(venv_env):
    alpha = dataclasses.replace(venv_env.cfg.consumers[0], pin_kind="none", pin_file="")
    cfg = FleetConfig(venv_env.cfg.worktree_root, (alpha,))
    row = only_row(refresh(venv_env.deps, venv_env.git, venv_env.gh, cfg, only=()))
    assert row.state == "failed" and "spec" in row.note
    assert venv_env.calls("uv") == []


def test_refresh_never_touches_checkout(venv_env):
    refresh(*venv_env.args, only=())
    assert venv_env.checkout_status() == venv_env.status_before and not venv_env.git_writes_in_checkout()
    assert _git(venv_env.clone, "for-each-ref") == venv_env.refs_before
    assert venv_env.deps.run.calls     # the spy saw something, so the assertion above is not vacuous


def test_report_never_touches_checkout(venv_env):
    report(*venv_env.args, only=())
    assert venv_env.checkout_status() == venv_env.status_before and not venv_env.git_writes_in_checkout()
    assert _git(venv_env.clone, "for-each-ref") == venv_env.refs_before


def test_report_runs_lock_free_with_a_note_when_the_lock_is_busy(venv_env):
    held = RunLock(venv_env.deps.dirs.run_lock)
    assert held.acquire(exclusive=True)
    try:
        row = only_row(report(*venv_env.args, only=()))
    finally:
        held.release()
    assert row.state == "drift" and "lock" in row.note


def test_refresh_with_a_busy_lock_is_a_usage_error(venv_env):
    held = RunLock(venv_env.deps.dirs.run_lock)
    assert held.acquire(exclusive=True)
    try:
        with pytest.raises(UsageError, match="lock busy"):
            refresh(*venv_env.args, only=())
    finally:
        held.release()
    assert venv_env.calls("uv") == []


def test_refresh_releases_the_lock_even_when_it_raises(venv_env):
    venv_env.deps.run.routes.insert(0, Route(match=("uv",), effect=lambda a, c, e: (_ for _ in ()).throw(OSError("x"))))
    with pytest.raises(OSError):
        refresh(*venv_env.args, only=())
    probe = RunLock(venv_env.deps.dirs.run_lock)
    assert probe.acquire(exclusive=True)
    probe.release()


def test_run_venvs_report_prints_a_line_and_the_hint_and_exits_ok(venv_env):
    assert run_venvs(*venv_env.run_args(), refresh=False, only=()) == FleetExit.OK
    out = venv_env.deps.out.getvalue()
    line = out.splitlines()[0]
    assert line.startswith("alpha") and str(venv_env.venv) in line and "drift" in line
    assert OLD[:12] in line and venv_env.lock_sha[:12] in line and "behind origin by 1; pull, then rerun" in line
    assert "pull the main checkouts, then run guard-fleet venvs --refresh" in out


def test_run_venvs_report_has_no_hint_when_nothing_drifted(venv_env):
    (venv_env.venv / "commit").write_text(venv_env.lock_sha + "\n")
    _git(venv_env.clone, "pull", "-q", "--ff-only")
    assert run_venvs(*venv_env.run_args(), refresh=False, only=()) == FleetExit.OK
    assert "guard-fleet venvs --refresh" not in venv_env.deps.out.getvalue()
    assert " ok " in venv_env.deps.out.getvalue()


def test_run_venvs_refresh_exit_codes(venv_env):
    assert run_venvs(*venv_env.run_args(), refresh=True, only=()) == FleetExit.OK
    assert "refreshed" in venv_env.deps.out.getvalue()
    assert "guard-fleet venvs --refresh" not in venv_env.deps.out.getvalue()


@pytest.mark.parametrize("how", ["in-use", "failed", "disagree", "missing"])
def test_run_venvs_refresh_is_blocked_by_a_skipped_or_failed_venv(venv_env, how):
    if how == "in-use":
        venv_env.pgrep_rc = 0
    elif how == "failed":
        venv_env.install_rc = 1
    elif how == "disagree":
        commit_files(venv_env.clone, "lock moves", {"guard.lock": "9" * 40 + "\n"})
    else:
        (venv_env.venv / "bin" / "python").unlink()
    assert run_venvs(*venv_env.run_args(), refresh=True, only=()) == FleetExit.BLOCKED
    assert how in venv_env.deps.out.getvalue()


def test_drifted_is_true_only_for_drift_or_disagree():
    def row(state):
        return VenvRow("a", Path("/v"), None, None, None, None, state, "")

    assert drifted([row("drift")]) and drifted([row("ok"), row("disagree")])
    assert not drifted([row(s) for s in ("ok", "missing", "in-use", "refreshed", "failed")])
    assert not drifted([])
