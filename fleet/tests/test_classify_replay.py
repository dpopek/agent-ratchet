"""The v4 replay: the classifier on this repository's real tags reproduces the spec §6.5 table."""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest

from classify_fixtures import REFINED_LAYOUT, REFINED_TRANSITION_GATES, tree_from
from fakes import real_git
from repos import commit_files, make_bare, make_clone, tag_annotated
from guard_fleet.classify import Level, classify_release, decide
from guard_fleet.classify.changes import classify_path
from guard_fleet.classify.decision import ReleaseClass, evidence_lines
from guard_fleet.classify.fingerprints import FINGERPRINT_TARGETS, REVIEWED, fingerprint
from guard_fleet.classify.surfaces import compute_surfaces
from guard_fleet.classify.tree import load_tree

FLEET_DIR = Path(__file__).resolve().parents[1]

REPLAY = [("v4.0.0", "v4.0.1", "BUMP"), ("v4.0.1", "v4.1.0", "BUMP"), ("v4.1.0", "v4.1.1", "BUMP"),
          ("v4.1.1", "v4.1.2", "SKIP"), ("v4.1.2", "v4.1.3", "BUMP"), ("v4.1.3", "v4.1.4", "BUMP"),
          ("v4.1.4", "v4.2.0", "BUMP"), ("v4.2.0", "v4.2.1", "BUMP"), ("v4.2.1", "v4.3.0", "BUMP"),
          ("v4.3.0", "v4.3.1", "BUMP"), ("v4.3.1", "v4.3.2", "BUMP"), ("v4.3.2", "v4.3.3", "SKIP"),
          ("v4.3.3", "v4.3.4", "SKIP")]
TAGS = sorted({tag for p, t, _ in REPLAY for tag in (p, t)}, key=lambda v: tuple(int(x) for x in v[1:].split(".")))


@dataclass(frozen=True)
class FakeExposure:
    level: Level


def _git_out(root: Path, *args: str) -> subprocess.CompletedProcess:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    return subprocess.run(("git", "-C", str(root), *args), env=env, capture_output=True, stdin=subprocess.DEVNULL,
                          timeout=30, check=False, text=True)


@pytest.fixture(scope="module")
def repo_root() -> Path:
    top = _git_out(FLEET_DIR, "rev-parse", "--show-toplevel")
    if top.returncode != 0:
        pytest.fail(f"not inside the repository: {top.stderr.strip()}")
    root = Path(top.stdout.strip())
    missing = [tag for tag in TAGS if _git_out(root, "rev-parse", "--verify", "--quiet", f"{tag}^{{commit}}").returncode]
    if missing:
        if os.environ.get("CI"):
            pytest.fail(f"tags not fetched: {missing}")
        pytest.skip("tags not fetched")
    return root


@pytest.fixture
def repo_git(repo_root):
    return real_git(), repo_root


def _rev(root: Path, rev: str) -> str:
    out = _git_out(root, "rev-parse", "--verify", f"{rev}^{{commit}}")
    assert out.returncode == 0, out.stderr
    return out.stdout.strip()


@pytest.fixture
def peel(repo_root):
    return lambda tag: _rev(repo_root, tag)


@pytest.fixture
def head_sha(repo_root):
    return lambda: _rev(repo_root, "HEAD")


@pytest.mark.parametrize("p,t,verdict", REPLAY)
def test_replay_table_for_core_only_consumer(repo_git, peel, p, t, verdict):
    git, root = repo_git
    rel = classify_release(git, root, peel(p), peel(t))
    assert decide(rel, FakeExposure(Level.CORE), include_unexposed=False) == verdict, evidence_lines(rel)


def test_reviewed_digests_group_the_tags_as_reviewed(repo_git, peel, head_sha):
    """Every tag's digests are reviewed (v4.0.x lacks php_profile_active); HEAD adds no new class."""
    git, root = repo_git
    by_target: dict[str, dict[str | None, list[str]]] = {f"{p}::{n}": {} for p, n in FINGERPRINT_TARGETS}
    for tag in TAGS:
        for target, value in fingerprint(load_tree(git, root, peel(tag))).items():
            by_target[target].setdefault(value, []).append(tag)
    groups = {target.rpartition("::")[2]: sorted(tags for tags in found.values()) for target, found in by_target.items()}
    v40, v41 = ["v4.0.0", "v4.0.1"], ["v4.1.0", "v4.1.1", "v4.1.2", "v4.1.3", "v4.1.4"]
    v42 = ["v4.2.0", "v4.2.1", "v4.3.0", "v4.3.1", "v4.3.2", "v4.3.3", "v4.3.4"]
    assert groups == {
        "php_profile_active": sorted([v40, v41 + v42]),
        "parse_guard_config_bytes": sorted([v40, v41, v42]),
        "load_guard_config_for_ref": sorted([v40, v41 + v42]),
        "_parse_profile": [v40 + v41 + v42],
        "_read_guard_config_for_ref": [v40 + v41 + v42],
        "default_guard_config": sorted([v40, v41, v42]),
    }
    assert by_target["src/agent_ratchet/php/scope.py::php_profile_active"].get(None) == v40
    for target, found in by_target.items():
        assert {d for d in found if d is not None} == REVIEWED[target], target
    head = fingerprint(load_tree(git, root, head_sha()))
    v434 = fingerprint(load_tree(git, root, peel("v4.3.4")))
    assert head == v434


def test_surfaces_at_v4_3_4(repo_git, peel):
    m = compute_surfaces(load_tree(*repo_git, peel("v4.3.4")))
    assert m.all_core_reason is None
    php = {k for k, v in m.level_of.items() if v is Level.PHP}
    assert php == {f"agent_ratchet.php.{n}" for n in ("codes", "compare", "directive_text", "directives", "extract",
                                                       "parser", "phpmd", "phpunit", "window_align")}
    assert {k for k, v in m.level_of.items() if v is Level.MAGENTO} == {"agent_ratchet.magento.compare"}
    for core in ("php", "php.scan", "php.scope", "magento", "magento.config", "magento.scan", "magento.xml_safe", "magento.di"):
        assert m.level_of[f"agent_ratchet.{core}"] is Level.CORE


def test_refinement_layout_makes_scan_modules_surface():
    # §6.13 shape on a synthetic tree: transition_scan imports php.scan and magento.scan only inside G-block
    # gates; php.scan's dedupe helper lives in a core module; magento.scan imports magento.di inside ungated
    # helpers and after its G-early, and magento.di imports xml_safe, as at v4.3.4.
    m = compute_surfaces(tree_from(REFINED_LAYOUT))
    assert m.all_core_reason is None
    for mod in ("php.scan", "magento.scan", "magento.di", "magento.xml_safe"):
        assert m.level_of[f"agent_ratchet.{mod}"] is not Level.CORE, mod
    assert m.level_of["agent_ratchet.violation_dedupe"] is Level.CORE
    assert {(g.module, g.lineno) for g in m.gates} >= REFINED_TRANSITION_GATES   # both G-blocks in transition_scan
    in_transition = {(g.module, g.lineno, g.kind, g.level) for g in m.gates if g.module == "agent_ratchet.transition_scan"}
    assert in_transition == {("agent_ratchet.transition_scan", 11, "block", Level.PHP),
                             ("agent_ratchet.transition_scan", 14, "block", Level.MAGENTO)}
    assert {(mod, line) for mod, line, _, _ in in_transition} == REFINED_TRANSITION_GATES


def v4_4_0_or_head(root: Path) -> str:
    """The v4.4.0 release once it is tagged (later src/ changes are legitimate), else this branch's HEAD."""
    tagged = _git_out(root, "rev-parse", "--verify", "--quiet", "v4.4.0^{commit}")
    return tagged.stdout.strip() if tagged.returncode == 0 else _rev(root, "HEAD")


def test_v4_4_0_or_head_prefers_the_tag(tmp_path):
    work = make_clone(make_bare(tmp_path, "alpha"), tmp_path / "alpha")
    first = commit_files(work, "c1", {"a": "1"})
    assert v4_4_0_or_head(work) == first
    tag_annotated(work, "v4.4.0")
    second = commit_files(work, "c2", {"a": "2"})
    assert v4_4_0_or_head(work) == first != second


def test_v4_4_0_diff_paths_are_metadata_or_version_only(repo_git, peel):
    # v4.3.4 vs v4.4.0 (or this branch's HEAD before the tag): every changed path is metadata (guards the Global
    # Constraints path discipline)
    git, root = repo_git
    rel = classify_release(git, root, peel("v4.3.4"), v4_4_0_or_head(root))
    assert rel.min_level is None, evidence_lines(rel)
    assert rel.fingerprint_mismatch == (), rel.fingerprint_mismatch


def test_refinement_diff_bumps_core_only_consumers(repo_git, peel, head_sha):
    # v4.4.0 -> HEAD moves transition_scan (core); php/scan.py is core at v4.4.0, so its surface is united to core
    git, root = repo_git
    rel = classify_release(git, root, peel("v4.4.0"), head_sha())
    assert rel.min_level is Level.CORE, evidence_lines(rel)
    assert decide(rel, FakeExposure(Level.CORE), include_unexposed=False) == "BUMP"
    assert "src/agent_ratchet/transition_scan.py [core]" in evidence_lines(rel)


@pytest.mark.parametrize("path,level,skipped_for,bumped_for", [
    ("src/agent_ratchet/php/scan.py", Level.PHP, Level.CORE, Level.PHP),
    ("src/agent_ratchet/magento/di.py", Level.MAGENTO, Level.CORE, Level.MAGENTO),
])
def test_later_scan_only_change_skips_core_only_consumers(repo_git, head_sha, path, level, skipped_for, bumped_for):
    # spec §6.13: once the layout is released, a change confined to a scan module no longer reaches core-only consumers
    tree = load_tree(*repo_git, head_sha())
    surfaces = compute_surfaces(tree)
    change = classify_path(path, "M", p_tree=tree, t_tree=tree, p_map=surfaces, t_map=surfaces)
    assert change.level is level, change
    rel = ReleaseClass(p="p", t="t", changes=(change,), min_level=change.level, all_core_reason=None,
                       fingerprint_mismatch=())
    assert decide(rel, FakeExposure(skipped_for), include_unexposed=False) == "SKIP"
    assert decide(rel, FakeExposure(bumped_for), include_unexposed=False) == "BUMP"
