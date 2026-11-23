"""Classifier II: changed paths, predicate and loader fingerprints, the release decision."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest

from classify_fixtures import SCOPE, tree_from
from fakes import real_git
from repos import commit_files, make_bare, make_clone
from guard_fleet.classify import Level, classify_release, decide
from guard_fleet.classify.changes import (ChangedPath, classify_path, version_only_pyproject,
                                          version_only_version_py)
from guard_fleet.classify.decision import ReleaseClass, evidence_lines
from guard_fleet.classify.fingerprints import FINGERPRINT_TARGETS, REVIEWED, fingerprint, mismatches
from guard_fleet.classify.surfaces import compute_surfaces
from guard_fleet.classify.tree import load_tree
from guard_fleet.git import Git

REPO_ROOT = Path(__file__).resolve().parents[2]
REPO_SRC = REPO_ROOT / "src/agent_ratchet"
SCOPE_PATH = "src/agent_ratchet/php/scope.py"
LOADER_PATH = "src/agent_ratchet/git_guard_io.py"
SCOPE_ID = f"{SCOPE_PATH}::php_profile_active"
PYPROJECT = b'[project]\nname = "agent-ratchet"\nversion = "4.3.4"\n\n[project.scripts]\nagent-ratchet = "agent_ratchet.cli:main"\n'


@dataclass(frozen=True)
class FakeExposure:
    level: Level


def defining_files() -> dict[str, bytes]:
    """Byte-exact copies of the files that define FINGERPRINT_TARGETS, from this repository (never invented)."""
    return {path: (REPO_ROOT / path).read_bytes() for path in {p for p, _ in FINGERPRINT_TARGETS}}


def narrowed_scope() -> bytes:
    """The real scope.py with the magento half of php_profile_active's predicate removed."""
    real = defining_files()[SCOPE_PATH]
    narrowed = real.replace(b' or "magento" in cfg.get("frameworks", ())', b"", 1)
    assert narrowed != real
    return narrowed


@pytest.fixture
def empty_maps():
    tree = tree_from({})
    m = compute_surfaces(tree)
    return {"p_tree": tree, "t_tree": tree, "p_map": m, "t_map": m}


def sides(p_files: dict[str, str], t_files: dict[str, str], *, p_modes=None, t_modes=None,
          p_pyproject=None, t_pyproject=None) -> dict:
    p_tree, t_tree = tree_from(p_files, pyproject=p_pyproject), tree_from(t_files, pyproject=t_pyproject)
    if p_modes:
        p_tree = type(p_tree)(p_tree.commit, p_tree.files, {**p_tree.modes, **p_modes}, p_tree.scripts, p_tree.pyproject)
    if t_modes:
        t_tree = type(t_tree)(t_tree.commit, t_tree.files, {**t_tree.modes, **t_modes}, t_tree.scripts, t_tree.pyproject)
    return {"p_tree": p_tree, "t_tree": t_tree, "p_map": compute_surfaces(p_tree), "t_map": compute_surfaces(t_tree)}


# -- changed paths -----------------------------------------------------------------------------------

@pytest.mark.parametrize("path", ["CHANGELOG.md", "README.md", "README.pl.md", "docs/x.md", "tests/t.py",
                                  ".github/workflows/ci.yml", "tools/d.py", "fleet/src/guard_fleet/cli.py", "uv.lock",
                                  "AGENTS.md", "LICENSE"])
def test_metadata_paths(path, empty_maps):
    got = classify_path(path, "M", **empty_maps)
    assert got == ChangedPath(path, "M", None, "metadata")


@pytest.mark.parametrize("path", [".gitignore", ".hgignore", "consumer/guard", "src/guard_core/__init__.py",
                                  "src/agent_ratchet/data.json", "Makefile", "docs2/x.md", "sub/README.md",
                                  "tests/.gitignore", "src/agent_ratchet/my-mod.py", "CHANGELOG.md.orig"])
def test_core_paths(path, empty_maps):
    got = classify_path(path, "M", **empty_maps)
    assert got.level is Level.CORE and got.reason, got


@pytest.mark.parametrize("p_modes,t_modes", [({}, {"src/agent_ratchet/x.py": "120000"}),
                                             ({"src/agent_ratchet/x.py": "120000"}, {}),
                                             ({}, {"src/agent_ratchet/x.py": "160000"})])
def test_symlink_under_src_is_core(p_modes, t_modes):
    php_only = {"src/agent_ratchet/x.py": "X = 1\n"}
    got = classify_path("src/agent_ratchet/x.py", "T", **sides(php_only, php_only, p_modes=p_modes, t_modes=t_modes))
    assert got.level is Level.CORE
    assert "symlink" in got.reason or "160000" in got.reason


# php.compare is reachable only behind php/scan.py's G-early; at P an ungated helper import makes it core.
SCAN_GATED = ("from agent_ratchet.php.scope import php_profile_active\n\n\n"
              "def php_scan(cfg):\n    if not php_profile_active(cfg):\n        return []\n"
              "    from agent_ratchet.php.compare import X\n    return [X]\n")
SCAN_UNGATED = "def php_scan(cfg):\n    from agent_ratchet.php.compare import X\n    return [X]\n"
GATED_LAYOUT = {"src/agent_ratchet/transition_scan.py": "from agent_ratchet.php.scan import php_scan\n",
                "src/agent_ratchet/php/scope.py": SCOPE, "src/agent_ratchet/php/scan.py": SCAN_GATED,
                "src/agent_ratchet/php/compare.py": "X = 1\n"}
COMPARE = "src/agent_ratchet/php/compare.py"


def test_src_module_takes_the_lower_level_of_both_sides():
    ungated = {**GATED_LAYOUT, "src/agent_ratchet/php/scan.py": SCAN_UNGATED}
    assert classify_path(COMPARE, "M", **sides(GATED_LAYOUT, GATED_LAYOUT)).level is Level.PHP
    assert classify_path(COMPARE, "M", **sides(ungated, GATED_LAYOUT)).level is Level.CORE
    assert classify_path(COMPARE, "M", **sides(GATED_LAYOUT, ungated)).level is Level.CORE


def test_module_on_one_side_takes_that_sides_level():
    without = {k: v for k, v in GATED_LAYOUT.items() if k != COMPARE}
    assert classify_path(COMPARE, "A", **sides(without, GATED_LAYOUT)).level is Level.PHP
    assert classify_path(COMPARE, "D", **sides(GATED_LAYOUT, without)).level is Level.PHP
    new_core = "src/agent_ratchet/report.py"
    assert classify_path(new_core, "A", **sides(without, {**without, new_core: "X = 1\n"})).level is Level.CORE


def test_pyproject_rule_compares_the_tree_pyprojects():
    bumped = PYPROJECT.replace(b"4.3.4", b"4.4.0")
    widened = bumped + b'extra = "agent_ratchet.cli:main"\n'
    assert classify_path("pyproject.toml", "M", **sides({}, {}, p_pyproject=PYPROJECT, t_pyproject=bumped)) \
        == ChangedPath("pyproject.toml", "M", None, "version-only")
    assert classify_path("pyproject.toml", "M", **sides({}, {}, p_pyproject=PYPROJECT, t_pyproject=widened)).level \
        is Level.CORE
    assert classify_path("pyproject.toml", "A", **sides({}, {}, t_pyproject=bumped)).level is Level.CORE


def test_version_py_rule_reads_the_tree_files():
    path = "src/agent_ratchet/version.py"
    p = {path: 'VERSION: str = "4.3.4"\n'}
    assert classify_path(path, "M", **sides(p, {path: 'VERSION: str = "4.4.0"\n'})) \
        == ChangedPath(path, "M", None, "version-only")
    assert classify_path(path, "M", **sides(p, {path: 'VERSION: str = "4.4.0"\nX = 1\n'})).level is Level.CORE
    assert classify_path(path, "A", **sides({}, {path: 'VERSION: str = "4.4.0"\n'})).level is Level.CORE
    linked = sides(p, {path: 'VERSION: str = "4.4.0"\n'}, t_modes={path: "120000"})
    assert classify_path(path, "T", **linked).level is Level.CORE


def test_version_only_pyproject():
    a = b'[project]\nname = "x"\nversion = "4.3.4"\n'; b = a.replace(b"4.3.4", b"4.4.0")
    assert version_only_pyproject(a, b)
    assert version_only_pyproject(a, a.replace(b'name = "x"', b'name = "x"  # comment'))
    assert not version_only_pyproject(b'[x]\nv = 1\n[project]\nversion="1"\n', b'[x]\nv = true\n[project]\nversion="2"\n')
    assert not version_only_pyproject(a, b.replace(b'"x"', b'"y"'))
    assert not version_only_pyproject(None, b)
    assert not version_only_pyproject(a, None)
    assert not version_only_pyproject(a, b"[project\n")
    assert not version_only_pyproject(a, b"\xff\xfe")


def test_version_only_version_py():
    assert version_only_version_py(b'VERSION: str = "4.3.4"\n', b'VERSION: str = "4.4.0"\n')     # the real form
    assert version_only_version_py(b'VERSION = "4.3.4"\n', b'VERSION = "4.4.0"\n')
    assert version_only_version_py(b'"""Doc."""\n\nVERSION: str = "4.3.4"\n', b'"""Doc."""\nVERSION: str = "4.4.0"\n')
    assert not version_only_version_py(b'VERSION: str = "4.3.4"\nMIN = "4.0.0"\n', b'VERSION: str = "4.4.0"\nMIN = "4.1.0"\n')
    assert not version_only_version_py(b'VERSION: str = "4.3.4"\n', b'VERSION: bytes = "4.4.0"\n')
    assert not version_only_version_py(b'VERSION: str = "1"\nVERSION = "1"\n', b'VERSION: str = "2"\nVERSION = "2"\n')
    assert not version_only_version_py(b'VERSION: str = "1"\n', b'VERSION: str = 2\n')
    assert not version_only_version_py(b'VERSION = "1"\n', b'VERSION = X = "2"\n')
    assert not version_only_version_py(b'VERSION: str = "1"\n', b'VERSION: str = "1"\ndef f():\n    VERSION = "x"\n')
    assert not version_only_version_py(b'X = "1"\n', b'X = "2"\n')
    assert not version_only_version_py(None, b'VERSION = "1"\n')
    assert not version_only_version_py(b'VERSION = "1"\n', b"VERSION = (\n")


def test_real_version_py_is_in_the_accepted_form():
    real = (REPO_SRC / "version.py").read_bytes()
    assert b'VERSION: str = "' in real
    assert version_only_version_py(real, real.replace(b'VERSION: str = "', b'VERSION: str = "9.', 1))


# -- fingerprints ------------------------------------------------------------------------------------

def test_fingerprint_targets_and_reviewed_ids_agree():
    ids = {f"{path}::{name}" for path, name in FINGERPRINT_TARGETS}
    assert set(REVIEWED) == ids and len(ids) == 6
    assert all(REVIEWED[i] and all(len(d) == 64 for d in REVIEWED[i]) for i in ids)


def test_this_repositorys_definitions_are_reviewed():
    tree = tree_from({path: data.decode("utf-8") for path, data in defining_files().items()})
    got = fingerprint(tree)
    assert all(got[i] in REVIEWED[i] for i in REVIEWED), got
    assert mismatches(tree) == ()


def test_absent_or_altered_definitions_are_mismatches():
    real = {path: data.decode("utf-8") for path, data in defining_files().items()}
    assert fingerprint(tree_from({}))[SCOPE_ID] is None
    assert mismatches(tree_from({k: v for k, v in real.items() if k != SCOPE_PATH})) == (SCOPE_ID,)
    assert mismatches(tree_from({**real, SCOPE_PATH: narrowed_scope().decode()})) == (SCOPE_ID,)
    rebound = real[SCOPE_PATH] + "\n\nphp_profile_active = bool\n"          # a later rebinding wins at runtime
    assert mismatches(tree_from({**real, SCOPE_PATH: rebound})) == (SCOPE_ID,)
    assert mismatches(tree_from({**real, SCOPE_PATH: real[SCOPE_PATH] + "\n(\n"})) == (SCOPE_ID,)


def test_a_changed_default_config_is_a_mismatch():
    # the loader returns default_guard_config() when the config is missing; turning php on there must not pass
    real = {path: data.decode("utf-8") for path, data in defining_files().items()}
    io_path = "src/agent_ratchet/git_guard_io.py"
    assert '"languages": [], "frameworks": []' in real[io_path]
    php_default = real[io_path].replace('"languages": [], "frameworks": []', '"languages": ["php"], "frameworks": []', 1)
    assert mismatches(tree_from({**real, io_path: php_default})) == (f"{io_path}::default_guard_config",)


def test_a_symlinked_definition_file_is_a_mismatch():
    real = {path: data.decode("utf-8") for path, data in defining_files().items()}
    tree = tree_from(real)
    tree = type(tree)(tree.commit, tree.files, {**tree.modes, SCOPE_PATH: "120000"}, tree.scripts)
    assert mismatches(tree) == (SCOPE_ID,)


# -- classify_release over a real repository ---------------------------------------------------------

def release_repo(tmp_path: Path, p_files: dict[str, bytes | str | None], t_files: dict[str, bytes | str | None]):
    work = make_clone(make_bare(tmp_path, "alpha"), tmp_path / "alpha")
    p = commit_files(work, "p", p_files)
    t = commit_files(work, "t", t_files)
    return work, p, t


def base_release_files() -> dict[str, bytes | str]:
    return {"pyproject.toml": PYPROJECT, "src/agent_ratchet/cli.py": "def main() -> int:\n    return 0\n",
            **defining_files(), **{k: v for k, v in GATED_LAYOUT.items() if k != SCOPE_PATH}}


def test_php_only_change_with_reviewed_definitions_skips_core(tmp_path):
    work, p, t = release_repo(tmp_path, base_release_files(), {COMPARE: "X = 2\n", "CHANGELOG.md": "x\n"})
    rel = classify_release(real_git(), work, p, t)
    assert (rel.p, rel.t) == (p, t)
    assert {c.path: c.level for c in rel.changes} == {COMPARE: Level.PHP, "CHANGELOG.md": None}
    assert (rel.min_level, rel.all_core_reason, rel.fingerprint_mismatch) == (Level.PHP, None, ())
    assert decide(rel, FakeExposure(Level.CORE), include_unexposed=False) == "SKIP"
    assert decide(rel, FakeExposure(Level.PHP), include_unexposed=False) == "BUMP"
    assert evidence_lines(rel) == [f"{COMPARE} [php]"]


@pytest.mark.parametrize("narrowed_side", ["p", "t"])
def test_fingerprint_mismatch_checks_both_sides(tmp_path, narrowed_side):
    base = base_release_files()
    if narrowed_side == "p":
        work, p, t = release_repo(tmp_path, {**base, SCOPE_PATH: narrowed_scope()}, {SCOPE_PATH: base[SCOPE_PATH]})
    else:
        work, p, t = release_repo(tmp_path, base, {SCOPE_PATH: narrowed_scope()})
    rel = classify_release(real_git(), work, p, t)
    assert rel.fingerprint_mismatch == (SCOPE_ID,)
    assert f"fingerprint mismatch: {SCOPE_ID}" in evidence_lines(rel)


def test_load_tree_carries_the_root_pyproject(tmp_path):
    work, p, t = release_repo(tmp_path, {"README.md": "x\n"}, {"pyproject.toml": PYPROJECT})
    assert load_tree(real_git(), work, p).pyproject is None
    assert load_tree(real_git(), work, t).pyproject == PYPROJECT


def test_metadata_only_release_has_no_level(tmp_path):
    bumped = PYPROJECT.replace(b"4.3.4", b"4.4.0")
    work, p, t = release_repo(tmp_path, base_release_files(), {"pyproject.toml": bumped, "docs/a.md": "a\n"})
    rel = classify_release(real_git(), work, p, t)
    assert rel.min_level is None and evidence_lines(rel) == []
    assert decide(rel, FakeExposure(Level.MAGENTO), include_unexposed=False) == "SKIP"


def test_all_core_reason_forces_core(tmp_path):
    work, p, t = release_repo(tmp_path, base_release_files(),
                              {"docs/a.md": "a\n", "src/agent_ratchet/bad.py": "def (\n"})
    rel = classify_release(real_git(), work, p, t)
    assert rel.min_level is Level.CORE
    assert rel.all_core_reason is not None and "src/agent_ratchet/bad.py" in rel.all_core_reason
    assert f"all core: {rel.all_core_reason}" in evidence_lines(rel)


@pytest.mark.parametrize("side", ["P", "T"])
@pytest.mark.parametrize("broken", [b"[project\n", b"\xff\xfe", b'[project.scripts]\nx = 1\n'])
def test_unreadable_pyproject_makes_the_release_all_core(tmp_path, side, broken):
    base = base_release_files()
    if side == "P":
        work, p, t = release_repo(tmp_path, {**base, "pyproject.toml": broken},
                                  {"pyproject.toml": PYPROJECT, COMPARE: "X = 4\n", "docs/a.md": "a\n"})
    else:
        work, p, t = release_repo(tmp_path, base, {"pyproject.toml": broken, COMPARE: "X = 4\n", "docs/a.md": "a\n"})
    rel = classify_release(real_git(), work, p, t)
    assert rel.all_core_reason is not None
    assert rel.all_core_reason.startswith(f"pyproject unparseable at {side}: pyproject.toml at ")
    assert rel.min_level is Level.CORE
    assert {c.path: c.level for c in rel.changes} == {"pyproject.toml": Level.CORE, COMPARE: Level.CORE,
                                                      "docs/a.md": None}
    assert decide(rel, FakeExposure(Level.CORE), include_unexposed=False) == "BUMP"
    assert f"all core: {rel.all_core_reason}" in evidence_lines(rel)


def test_classify_release_is_cached_per_pair(tmp_path):
    work, p, t = release_repo(tmp_path, base_release_files(), {COMPARE: "X = 3\n"})
    calls: list[tuple[str, ...]] = []
    inner = real_git()

    def counting(argv, **kw):
        calls.append(tuple(argv))
        return inner.run(argv, **kw)

    git = Git(counting, inner.env, lambda s: None)
    first = classify_release(git, work, p, t)
    diffs = sum(1 for a in calls if "diff" in a)
    assert diffs == 1
    assert classify_release(git, work, p, t) is first
    assert sum(1 for a in calls if "diff" in a) == 1
    assert classify_release(git, work, t, p) is not first


# -- decision ----------------------------------------------------------------------------------------

PHP_REL = ReleaseClass("p", "t", (ChangedPath("src/agent_ratchet/php/compare.py", "M", Level.PHP, ""),),
                       Level.PHP, None, ())


@pytest.mark.parametrize("min_level,exposure,verdict", [
    (Level.PHP, Level.CORE, "SKIP"), (Level.PHP, Level.PHP, "BUMP"), (Level.PHP, Level.MAGENTO, "BUMP"),
    (Level.MAGENTO, Level.PHP, "SKIP"), (Level.MAGENTO, Level.MAGENTO, "BUMP"), (Level.CORE, Level.CORE, "BUMP"),
    (None, Level.MAGENTO, "SKIP"),
])
def test_decide_compares_exposure_with_the_lowest_changed_level(min_level, exposure, verdict):
    rel = ReleaseClass("p", "t", (), min_level, None, ())
    assert decide(rel, FakeExposure(exposure), include_unexposed=False) == verdict


def test_fingerprint_mismatch_exposes_every_surface():
    rel = ReleaseClass("p", "t", (ChangedPath("src/agent_ratchet/php/compare.py", "M", Level.PHP, ""),), Level.PHP, None, ("x::y",))
    assert decide(rel, FakeExposure(Level.CORE), include_unexposed=False) == "BUMP"
    assert decide(PHP_REL, FakeExposure(Level.CORE), include_unexposed=False) == "SKIP"
    magento_only = ReleaseClass("p", "t", (), Level.MAGENTO, None, ("x::y",))
    assert decide(magento_only, FakeExposure(Level.CORE), include_unexposed=False) == "BUMP"
    metadata_only = ReleaseClass("p", "t", (), None, None, ("x::y",))
    assert decide(metadata_only, FakeExposure(Level.CORE), include_unexposed=False) == "SKIP"


def test_include_unexposed_turns_skip_into_bump():
    rel = ReleaseClass("p", "t", (), None, None, ())
    assert decide(rel, FakeExposure(Level.CORE), include_unexposed=True) == "BUMP"
    assert decide(PHP_REL, FakeExposure(Level.CORE), include_unexposed=True) == "BUMP"


def test_evidence_lines_tag_every_non_metadata_change():
    rel = ReleaseClass("p", "t", (ChangedPath("README.md", "M", None, "metadata"),
                                  ChangedPath("src/agent_ratchet/a.py", "M", Level.CORE, "module"),
                                  ChangedPath("src/agent_ratchet/php/b.py", "A", Level.PHP, "module"),
                                  ChangedPath("src/agent_ratchet/magento/c.py", "D", Level.MAGENTO, "module")),
                       Level.CORE, "at T: parse error x", ("a::b", "c::d"))
    assert evidence_lines(rel) == ["src/agent_ratchet/a.py [core]", "src/agent_ratchet/php/b.py [php]",
                                   "src/agent_ratchet/magento/c.py [magento]", "all core: at T: parse error x",
                                   "fingerprint mismatch: a::b, c::d"]
