from pathlib import Path

import pytest

from fakes import real_git
from guard_fleet.classify import Level
from guard_fleet.config import Consumer
from guard_fleet.exposure import SCAN_EXCLUDES, TreeScan, compute_exposure, resolve_guard_exec, tree_scan
from guard_fleet.git import GitError
from guard_fleet.lockfile import LockSpec
from guard_fleet.profile import parse_profile
from repos import commit_files, make_bare, make_clone, sha_of

EMPTY_SCAN = TreeScan(frozenset(), ())


@pytest.fixture
def alpha(tmp_path):
    return make_consumer(tmp_path)


def make_consumer(tmp_path, surfaces=frozenset()):
    return Consumer(short="alpha", dir=tmp_path / "alpha", slug="owner/alpha", default_branch="main",
                    pin_kind="none", pin_file=None, ring=1, ci="if-run", ci_wait_min=20, deploy_workflows=(),
                    quiet_before_merge=(), commit_env={}, node_modules=False, hook_needs=(), venvs=(),
                    surfaces=frozenset(surfaces), confirm_note="")


@pytest.fixture
def consumer_repo(tmp_path):
    def build(files):
        repo = make_clone(make_bare(tmp_path / "bare", "alpha"), tmp_path / "work")
        commit_files(repo, "tree", files)
        return repo, sha_of(repo, "HEAD")
    return build


@pytest.mark.parametrize("raw,lock,surfaces,level", [
    (None, LockSpec("a" * 40), (), Level.CORE),
    (b'{"languages": ["php"]}', LockSpec("a" * 40), (), Level.PHP),
    (b'{"languages": ["php"], "frameworks": ["magento"]}', LockSpec("a" * 40), (), Level.MAGENTO),
    (None, LockSpec("a" * 40, "php"), (), Level.PHP),
    (None, LockSpec("a" * 40, "magento"), (), Level.MAGENTO),
    (None, LockSpec("a" * 40), ("php",), Level.PHP),
    (None, LockSpec("a" * 40), ("magento",), Level.MAGENTO),
    (None, LockSpec("a" * 40), ("php", "magento"), Level.MAGENTO)])
def test_exposure_is_the_max_of_its_sources(tmp_path, raw, lock, surfaces, level):
    e = compute_exposure(parse_profile(raw), lock, make_consumer(tmp_path, surfaces), EMPTY_SCAN)
    assert e.level is level
    assert (e.reasons == ()) == (level is Level.CORE)


def test_unparseable_config_exposes_everything(alpha):
    e = compute_exposure(parse_profile(b"{not json"), LockSpec("a" * 40), alpha, EMPTY_SCAN)
    assert e.level is Level.MAGENTO and "unparseable" in " ".join(e.reasons)


def test_extras_php_lock_gives_php_exposure(alpha):
    assert compute_exposure(parse_profile(None), LockSpec("a" * 40, "php"), alpha, EMPTY_SCAN).level is Level.PHP


def test_scan_levels_raise_exposure_and_the_scan_is_kept(alpha):
    scan = TreeScan(frozenset({Level.PHP}), ("agent_ratchet.php imported: x.py:1 [php]",))
    e = compute_exposure(parse_profile(None), LockSpec("a" * 40), alpha, scan)
    assert e.level is Level.PHP and e.tree_scan is scan and "x.py:1" in e.reasons[0]


def test_tree_scan_adds_surface_and_opaque_guard_exec_adds_every_surface(consumer_repo):
    repo, d = consumer_repo({"tools/x.py": "import agent_ratchet.php.compare\n",
                             "Makefile": "x:\n\tsh scripts/guard exec -- sh -c \"$CMD\"\n"})
    scan = tree_scan(real_git(), repo, d)
    assert scan.levels == {Level.PHP, Level.MAGENTO} and any("opaque guard exec" in e for e in scan.evidence)
    assert any(e.startswith("opaque guard exec: Makefile:2") for e in scan.evidence)
    assert any("tools/x.py:1" in e and "[php]" in e for e in scan.evidence)


def test_magento_import_is_magento(consumer_repo):
    repo, d = consumer_repo({"tools/x.py": "from agent_ratchet.magento.di import analyze_di\n"})
    assert tree_scan(real_git(), repo, d).levels == {Level.MAGENTO}


def test_guard_exec_tracked_script_is_resolved(consumer_repo):
    repo, d = consumer_repo({"scripts/a.sh": "exec sh scripts/guard exec -- python3 scripts/a.py \"$@\"\n",
                             "scripts/a.py": "from agent_ratchet.baseline_diff import evaluate_baseline_diff\n"})
    assert tree_scan(real_git(), repo, d).levels == frozenset()


def test_guard_exec_opaque_adds_every_surface(consumer_repo):
    repo, d = consumer_repo({"scripts/a.sh": "exec sh scripts/guard exec -- python3 scripts/a.py\n",
                             "scripts/a.py": "import importlib\nimportlib.import_module('agent_ratchet.cli')\n"})
    assert Level.MAGENTO in tree_scan(real_git(), repo, d).levels


def test_guard_exec_lock_from_is_skipped(consumer_repo):
    repo, d = consumer_repo({"Makefile": "x:\n\tscripts/guard exec --lock-from HEAD -- python3 -m agent_ratchet.cli scan\n"})
    assert tree_scan(real_git(), repo, d).levels == frozenset()


def test_doc_mentions_are_not_scanned(consumer_repo):
    repo, d = consumer_repo({"docs/x.md": "agent_ratchet.php\n", "README.md": "scripts/guard exec -- foo\n",
                             "docs/sub/y.txt": "agent_ratchet.magento\n"})
    assert tree_scan(real_git(), repo, d).levels == frozenset()
    assert SCAN_EXCLUDES == (":(exclude,glob)**/*.md", ":(exclude,glob)docs/**")


def test_the_guard_wrapper_itself_is_not_scanned(consumer_repo):
    repo, d = consumer_repo({"scripts/guard": "#!/bin/sh\n# scripts/guard exec -- $CMD\n"})
    assert tree_scan(real_git(), repo, d).levels == frozenset()


def test_unknown_tree_is_a_git_error(consumer_repo):
    repo, _ = consumer_repo({"a": "1"})
    with pytest.raises(GitError):
        tree_scan(real_git(), repo, "f" * 40)


@pytest.mark.parametrize("command,level", [
    ("scripts/guard exec -- python3 -m agent_ratchet.php.compare", Level.PHP),
    ("scripts/guard exec python -I -m agent_ratchet.magento.di", Level.MAGENTO),
    ("scripts/guard exec -- python3 -m agent_ratchet.cli scan", Level.CORE),
    ("scripts/guard exec -- python3 -m pytest -q", Level.CORE),
    ("scripts/guard exec -- python3 scripts/ok.py", Level.CORE),
    ("scripts/guard exec -- agent-ratchet scan", Level.CORE),
    ("scripts/guard exec agent-ratchet scan", Level.CORE),
    ("scripts/guard exec -- python3 -m $MOD", Level.MAGENTO),
    ("scripts/guard exec -- python3 -c 'import x'", Level.MAGENTO),
    ("scripts/guard exec -- $CMD", Level.MAGENTO),
    ("scripts/guard exec --", Level.MAGENTO),
    ("scripts/guard exec --lock-from", Level.MAGENTO),
    ("scripts/guard exec -- python3 \"unterminated", Level.MAGENTO),
    ("scripts/guard exec -- python3 scripts/missing.py", Level.MAGENTO),
    ("scripts/guard exec -- python3 ../outside.py", Level.MAGENTO)])
def test_resolve_guard_exec_forms(consumer_repo, command, level):
    repo, d = consumer_repo({"scripts/ok.py": "print(1)\n"})
    got, evidence = resolve_guard_exec(real_git(), repo, d, f"Makefile:7:\t{command}")
    assert got is level
    opaque = "agent_ratchet.magento" not in command and level is Level.MAGENTO
    assert opaque == evidence.startswith("opaque guard exec: Makefile:7")
