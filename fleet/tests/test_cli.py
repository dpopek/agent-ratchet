"""The real CLI: argument parsing, the startup order and the exit-code mapping (spec 6.12)."""

import pytest

from guard_fleet import cli
from guard_fleet.exits import Cancelled, NoHelper
from guard_fleet.gh import GhAuthError, GhNetworkError
from guard_fleet.git import GitNetworkError
from guard_fleet.proc import Result
from test_release import ReleaseEnv
from test_roll import TAG

SHA = "a" * 40


def test_help_exits_0(capsys):
    assert cli.main(["--help"]) == 0
    assert "--expect-sha" in capsys.readouterr().out


def test_missing_expect_sha_is_2():
    assert cli.main(["status"]) == 2


def test_no_subcommand_is_2(capsys):
    assert cli.main(["--expect-sha", SHA]) == 2


def test_expect_sha_mismatch_is_3(monkeypatch, capsys):
    monkeypatch.setattr(cli, "installed_sha", lambda: "b" * 40)
    monkeypatch.setattr(cli, "load_config", lambda *a, **k: pytest.fail("config read before the sha check"))
    assert cli.main(["--expect-sha", SHA, "status"]) == 3
    assert "--expect-sha" in capsys.readouterr().err


def test_expect_sha_not_hex_is_2(monkeypatch):
    monkeypatch.setattr(cli, "installed_sha", lambda: SHA)
    assert cli.main(["--expect-sha", "A" * 40, "status"]) == 2


@pytest.fixture
def cli_env(tmp_path, fleet_home, monkeypatch):
    """ReleaseEnv behind cli.main: alpha's lock is unparseable (plan BLOCKED); gamma merges at a foreign head."""
    env = ReleaseEnv(tmp_path, fleet_home, locks={"alpha": "not a lock\n"})
    orig = env.fake._pr_merge

    def merge(argv, slug, e):
        res = orig(argv, slug, e)
        if slug == "owner/gamma":
            next(p for p in env.fake.prs[slug] if p["number"] == int(argv[3]))["headRefOid"] = "e" * 40
        return res
    env.fake._pr_merge = merge
    monkeypatch.setattr(cli, "default_deps", lambda: env.deps)
    monkeypatch.setattr(cli, "installed_sha", lambda: env.running_sha)
    return env


def test_exit_precedence_end_to_end(cli_env):
    cli_env.deps.environ["ALLOW_GUARD_LOCK_UPDATE"] = "1"
    assert cli.main(["--expect-sha", cli_env.running_sha, "release", TAG]) == 6   # FAILED beats BLOCKED
    assert "ALLOW_GUARD_LOCK_UPDATE" not in cli_env.deps.environ                  # read once, popped
    end = cli_env.end()
    assert end["alpha"].startswith("BLOCKED plan") and end["gamma"].startswith("FAILED merge")
    assert end["beta"] == "LANDED"


def test_release_refusal_names_the_command_as_typed_without_the_launcher_sha(cli_env):
    assert cli.main(["--expect-sha", cli_env.running_sha, "release", TAG, "--hold-ring-2"]) == 2
    assert f"Run: ALLOW_GUARD_LOCK_UPDATE=1 guard-fleet release {TAG} --hold-ring-2\n" in cli_env.out()


def test_usage_error_message_goes_to_stderr(cli_env):
    assert cli.main(["--expect-sha", cli_env.running_sha, "plan", "v4.0.9"]) == 2
    assert "v4.0.9 does not exist" in cli_env.deps.err.getvalue()


def test_self_check_runs_before_dispatch(cli_env, monkeypatch):
    monkeypatch.setattr(cli, "run_status", lambda *a: pytest.fail("dispatched"))
    monkeypatch.setattr(cli, "installed_sha", lambda: "c" * 40)    # no tag peels to it
    assert cli.main(["--expect-sha", "c" * 40, "status"]) == 2
    assert "self-check" in cli_env.deps.err.getvalue()


def test_plan_prints_the_table_and_exits_with_its_code(cli_env):
    assert cli.main(["--expect-sha", cli_env.running_sha, "plan", TAG]) == 1   # alpha is BLOCKED
    assert f"Target {TAG}" in cli_env.out()


@pytest.mark.parametrize("exc, code", [
    (Cancelled("timeout"), 4), (NoHelper("no swiftc"), 5), (GhAuthError(None, "auth"), 4),
    (GhNetworkError(None, "lost"), 4), (GitNetworkError(Result(("git",), 128, b"", b"lost", False)), 4)])
def test_exceptions_map_to_exit_codes(cli_env, monkeypatch, exc, code):
    def boom(*a, **k):
        raise exc
    monkeypatch.setattr(cli, "run_land", boom)
    assert cli.main(["--expect-sha", cli_env.running_sha, "land", TAG]) == code
    if code == 4 and not isinstance(exc, Cancelled):
        assert f"Resume: guard-fleet land {TAG}" in cli_env.deps.err.getvalue()


def test_any_other_exception_propagates(cli_env, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("a bug")
    monkeypatch.setattr(cli, "run_status", boom)
    with pytest.raises(RuntimeError, match="a bug"):
        cli.main(["--expect-sha", cli_env.running_sha, "status"])
