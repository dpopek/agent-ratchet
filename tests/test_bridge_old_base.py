"""Bridge: the previous release (3.2.0), as the trusted base in CI, must judge the first bump to this release."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

import pytest

from guard_repo_harness import REPO_ROOT, _commit_files
from test_lock_policy import LOCK_PATH, SHIM_PATH, _consumer, _shim, _tag_remote

pytestmark = pytest.mark.bridge

OLD_TAG = "v3.2.0"

# Runs under `python -I` against the extracted old release only; this checkout is never importable from it.
_PROBE = """
import json, sys
sys.path.insert(0, sys.argv[1])
import agent_ratchet
from agent_ratchet.git_guard_io import GuardAnalysisError
from agent_ratchet.lock_policy import verify_lock_transition
assert agent_ratchet.__file__.startswith(sys.argv[1]), agent_ratchet.__file__
base, head, cwd, url = sys.argv[2:6]
try:
    print(json.dumps({"errors": verify_lock_transition(base, head, cwd=cwd, local=False, repo_url=url)}))
except GuardAnalysisError as exc:
    print(json.dumps({"analysis_error": str(exc)}))
"""


@pytest.fixture(scope="module")
def old_base_src(tmp_path_factory: pytest.TempPathFactory) -> Path:
    if subprocess.run(["git", "rev-parse", "-q", "--verify", f"refs/tags/{OLD_TAG}^{{commit}}"], cwd=REPO_ROOT, capture_output=True).returncode != 0:
        pytest.skip(f"tag {OLD_TAG} is not available in this clone")
    dest = tmp_path_factory.mktemp("old_base")
    archive = subprocess.run(["git", "archive", OLD_TAG], cwd=REPO_ROOT, capture_output=True, check=True).stdout
    subprocess.run(["tar", "-x", "-C", str(dest)], input=archive, check=True)
    return dest / "src"


def _old_base_judges(src: Path, repo: Path, base: str, head: str, url: str) -> dict[str, object]:
    res = subprocess.run([sys.executable, "-I", "-c", _PROBE, str(src), base, head, str(repo), url], capture_output=True, text=True, cwd=repo)
    assert res.returncode == 0, res.stderr
    return json.loads(res.stdout)


def _bump(tmp_path: Path, tags: list[tuple[str, str, bool]], target: str, lock_suffix: str) -> tuple[Path, str, str, str]:
    (tmp_path / "remote").mkdir()
    url, shas = _tag_remote(tmp_path / "remote", tags)
    repo, base = _consumer(tmp_path / "consumer", {LOCK_PATH: shas["c1"] + "\n", SHIM_PATH: _shim("c1")})
    shim_tag = "c2" if target == "c2" else "c1"
    head = _commit_files(repo, "chore: bump guard", {LOCK_PATH: f"{shas[target]}\n{lock_suffix}", SHIM_PATH: _shim(shim_tag)})
    return repo, base, head, url


_TAGS = [("v3.0.0", "c1", True), ("v3.3.0", "c2", True), ("v4.0.0", "s1", True)]


def test_old_base_accepts_sha_only_bump_to_the_candidate(tmp_path: Path, old_base_src: Path) -> None:
    repo, base, head, url = _bump(tmp_path, _TAGS, "c2", "")
    assert _old_base_judges(old_base_src, repo, base, head, url) == {"errors": []}


def test_old_base_rejects_extras_in_first_bump(tmp_path: Path, old_base_src: Path) -> None:
    repo, base, head, url = _bump(tmp_path, _TAGS, "c2", "EXTRAS=none\n")
    verdict = _old_base_judges(old_base_src, repo, base, head, url)
    assert "Malformed guard.lock" in str(verdict.get("analysis_error")), verdict


def test_old_base_rejects_jump_to_a_v4_tag(tmp_path: Path, old_base_src: Path) -> None:
    repo, base, head, url = _bump(tmp_path, _TAGS, "s1", "")
    errors = _old_base_judges(old_base_src, repo, base, head, url).get("errors")
    assert isinstance(errors, list) and any("carries no annotated v3.x.y release tag" in e for e in errors), errors
