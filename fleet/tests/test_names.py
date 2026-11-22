from pathlib import Path

import pytest

from guard_fleet.config import load_config
from guard_fleet.names import VERSION_RE, branch_for, is_fleet_worktree, parse_fleet_branch, worktree_for
from test_config import ALPHA_IF_RUN, BETA_REQUIRED, write


@pytest.fixture
def cfg(tmp_path):
    return load_config(write(tmp_path, ALPHA_IF_RUN, BETA_REQUIRED), home=tmp_path)


@pytest.mark.parametrize("name,version", [
    ("chore/agent-ratchet-4.4.1", "4.4.1"),
    ("chore/agent-ratchet-3.2.0", "3.2.0"),
    ("chore/agent-ratchet-migrate-imports", None),
    ("chore/agent-ratchet-4.4", None),
    ("chore/agent-ratchet-4.4.1\n", None),
    ("chore/agent-ratchet-4.4.1-rc1", None),
    ("chore/agent-ratchet-٤.4.1", None),     # an Arabic-Indic digit is not a version digit
    ("feature/agent-ratchet-4.4.1", None),
    ("", None)])
def test_parse_fleet_branch(name, version):
    assert parse_fleet_branch(name) == version


def test_version_re_is_ascii_digits_only():
    assert VERSION_RE.fullmatch("10.0.12") and not VERSION_RE.fullmatch("1.2")


def test_branch_for_round_trips_and_rejects_bad_versions():
    assert branch_for("4.4.1") == "chore/agent-ratchet-4.4.1"
    assert parse_fleet_branch(branch_for("4.4.1")) == "4.4.1"
    for bad in ("v4.4.1", "4.4", "4.4.1\n", "../x"):
        with pytest.raises(ValueError):
            branch_for(bad)


def test_worktree_for_is_root_short_wt_version(cfg, tmp_path):
    alpha = cfg.by_short("alpha")
    assert worktree_for(cfg, alpha, "4.4.1") == tmp_path / "wt" / "alpha-wt-agent-ratchet-4.4.1"
    with pytest.raises(ValueError):
        worktree_for(cfg, alpha, "4.4")


def test_is_fleet_worktree_needs_the_matching_path_and_branch(cfg, tmp_path):
    alpha, beta = cfg.by_short("alpha"), cfg.by_short("beta")
    mine = tmp_path / "wt" / "alpha-wt-agent-ratchet-4.4.1"
    assert is_fleet_worktree(cfg, alpha, mine, "chore/agent-ratchet-4.4.1")
    assert not is_fleet_worktree(cfg, beta, mine, "chore/agent-ratchet-4.4.1")        # another consumer's name
    assert not is_fleet_worktree(cfg, alpha, mine, "chore/agent-ratchet-4.4.2")       # branch of another version
    assert not is_fleet_worktree(cfg, alpha, mine, None)                              # detached
    assert not is_fleet_worktree(cfg, alpha, mine, "chore/agent-ratchet-migrate-imports")
    assert not is_fleet_worktree(cfg, alpha, tmp_path / "elsewhere" / mine.name, "chore/agent-ratchet-4.4.1")
    assert not is_fleet_worktree(cfg, alpha, Path("relative"), "chore/agent-ratchet-4.4.1")
