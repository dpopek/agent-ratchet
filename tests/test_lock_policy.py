"""agent-ratchet 3 pin protection: guard.lock / scripts/guard transition rules (spec 10.1)."""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys

import pytest

from agent_ratchet import ai_slop_scanner, lock_policy, test_baseline_integrity
from agent_ratchet.git_guard_io import GuardAnalysisError, is_protected_governance_path
from agent_ratchet.lock_policy import (
    GUARD_CORE_URL,
    LEGACY_MANIFEST_PATH,
    LOCK_PATH,
    SHIM_PATH,
    lock_check_is_local,
    read_lock,
    release_tag_for,
    released_descendant_error,
    staged_lock_errors,
    verify_lock_transition,
)

sys.path.insert(0, str(Path(__file__).resolve().parent))
from guard_repo_harness import _commit_files, _git, _init_guard_repo, _run_baseline_guard, _run_scanner, _write_files

ENV_MSG = "guard.lock/scripts/guard change requires ALLOW_GUARD_LOCK_UPDATE=1"
DELETED_MSG = "guard.lock was deleted"
LEFTOVER_MSG = "remove scripts/audit/guard_manifest.json when adopting guard.lock"
LEGACY_DELETED_MSG = "scripts/audit/guard_manifest.json was deleted without adopting guard.lock"
LEGACY_CHANGED_MSG = "scripts/audit/guard_manifest.json changed; agent-ratchet 3 is pinned by guard.lock"
MANIFEST = '{"guard_version": "2.3.3", "files": {}, "baseline_migrations": []}\n'
ABSENT_SHA = "ab" * 20


def _shim(tag: str) -> str:
    return f"#!/bin/sh\n# guard shim {tag}\nexec uvx agent-ratchet \"$@\"\n"


class Remote:
    def __init__(self, url: str, c1: str, c2: str, c3: str) -> None:
        self.url, self.c1, self.c2, self.c3 = url, c1, c2, c3


@pytest.fixture(scope="module")
def remote(tmp_path_factory: pytest.TempPathFactory) -> Remote:
    """Bare agent-ratchet stand-in: c1 <- c2 <- c3; v3.0.0 annotated on c1, v3.0.1 annotated on c2, v3.0.2-light lightweight on c3."""
    work = tmp_path_factory.mktemp("agent_ratchet_work")
    for args in (["init", "-q"], ["config", "user.email", "guard@example.com"], ["config", "user.name", "Guard Test"]):
        _git(work, *args)
    shas = []
    for idx, tag in enumerate(("c1", "c2", "c3"), start=1):
        sha = _commit_files(work, f"release {idx}", {"consumer/guard": _shim(tag), "src/agent_ratchet/__init__.py": f"# {idx}\n"})
        shas.append(sha)
    _git(work, "tag", "-a", "v3.0.0", "-m", "v3.0.0", shas[0])
    _git(work, "tag", "-a", "v3.0.1", "-m", "v3.0.1", shas[1])
    _git(work, "tag", "v3.0.2-light", shas[2])
    bare = tmp_path_factory.mktemp("agent_ratchet_remote") / "agent-ratchet.git"
    subprocess.run(["git", "clone", "--bare", "--quiet", str(work), str(bare)], check=True)
    return Remote(bare.as_uri(), *shas)


@pytest.fixture(autouse=True)
def _no_operator_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ALLOW_GUARD_LOCK_UPDATE", raising=False)


def _consumer(tmp_path: Path, files: dict[str, str]) -> tuple[Path, str]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    repo = _init_guard_repo(str(tmp_path))
    return repo, _commit_files(repo, "chore: base", {"src/app.py": "A = 1\n", **files}, include_guards=True)


def _stage(repo: Path, files: dict[str, str]) -> None:
    _write_files(repo, files)
    _git(repo, "add", *files)


def test_agent_ratchet_url_is_hard_coded(tmp_path: Path) -> None:
    assert GUARD_CORE_URL == "https://github.com/dpopek/agent-ratchet"
    assert (LOCK_PATH, SHIM_PATH, LEGACY_MANIFEST_PATH) == ("guard.lock", "scripts/guard", "scripts/audit/guard_manifest.json")
    env = {"PATH": "/usr/bin:/bin", "PYTHONPATH": str(Path(lock_policy.__file__).resolve().parents[1]), "GUARD_CORE_URL": (tmp_path / "evil.git").as_uri()}
    probe = "from agent_ratchet.lock_policy import GUARD_CORE_URL; print(GUARD_CORE_URL)"
    out = subprocess.run([sys.executable, "-c", probe], env=env, capture_output=True, text=True, check=True).stdout.strip()
    assert out == "https://github.com/dpopek/agent-ratchet"


def test_lock_check_is_local_only_for_uncommitted_targets() -> None:
    assert lock_check_is_local("") and lock_check_is_local(None) and lock_check_is_local("WORKTREE")
    assert not lock_check_is_local("HEAD") and not lock_check_is_local("0" * 40)


def test_read_lock_format(tmp_path: Path) -> None:
    repo, _ = _consumer(tmp_path, {})
    assert read_lock("", cwd=str(repo)) is None
    sha = "0123456789abcdef0123456789abcdef01234567"
    for good in (sha + "\n", sha):
        _stage(repo, {LOCK_PATH: good})
        assert read_lock("", cwd=str(repo)) == sha
    for bad in (sha + "\r\n", sha.upper() + "\n", sha[:39] + "\n", f"{sha}\n{sha}\n", sha + "\n\n", " " + sha + "\n"):
        _stage(repo, {LOCK_PATH: bad})
        with pytest.raises(GuardAnalysisError):
            read_lock("", cwd=str(repo))


def test_unchanged_lock_ok(tmp_path: Path, remote: Remote) -> None:
    repo, base = _consumer(tmp_path, {LOCK_PATH: remote.c1 + "\n", SHIM_PATH: _shim("c1")})
    _stage(repo, {"src/app.py": "A = 2\n"})
    unreachable = (tmp_path / "missing.git").as_uri()
    assert verify_lock_transition("HEAD", "", cwd=str(repo), local=True, repo_url=unreachable) == []
    head = _commit_files(repo, "feat: app", {})
    assert verify_lock_transition(base, head, cwd=str(repo), local=False, repo_url=unreachable) == []


def test_lock_deletion_rejected(tmp_path: Path, remote: Remote) -> None:
    repo, base = _consumer(tmp_path, {LOCK_PATH: remote.c1 + "\n", SHIM_PATH: _shim("c1")})
    _git(repo, "rm", "-q", LOCK_PATH)
    for local in (True, False):
        assert verify_lock_transition("HEAD", "", cwd=str(repo), local=local, repo_url=remote.url) == [DELETED_MSG]
    for runner in (_run_scanner, _run_baseline_guard):
        res = runner(repo, "--staged-only")
        assert res.returncode == 2, res.stderr + res.stdout
        assert DELETED_MSG in res.stderr
    _git(repo, "commit", "-q", "-m", "chore: drop lock")
    r_base = _run_baseline_guard(repo, "--require-base-ref", "--commit-range", f"{base}..HEAD")
    assert r_base.returncode == 1 and DELETED_MSG in r_base.stderr
    r_scan = _run_scanner(repo, "--commit-range", f"{base}..HEAD")
    assert r_scan.returncode == 1 and DELETED_MSG in r_scan.stderr


def test_local_change_without_env_rejected(tmp_path: Path, remote: Remote) -> None:
    repo, _ = _consumer(tmp_path, {LOCK_PATH: remote.c1 + "\n", SHIM_PATH: _shim("c1")})
    _stage(repo, {LOCK_PATH: remote.c2 + "\n"})
    assert verify_lock_transition("HEAD", "", cwd=str(repo), local=True, repo_url=remote.url) == [ENV_MSG]
    res = _run_scanner(repo, "--staged-only")
    assert res.returncode == 2 and ENV_MSG in res.stderr


def test_local_change_with_env_and_tag_ok(tmp_path: Path, remote: Remote, monkeypatch: pytest.MonkeyPatch) -> None:
    repo, _ = _consumer(tmp_path, {LOCK_PATH: remote.c1 + "\n", SHIM_PATH: _shim("c1")})
    _stage(repo, {LOCK_PATH: remote.c2 + "\n", SHIM_PATH: _shim("c2")})
    monkeypatch.setenv("ALLOW_GUARD_LOCK_UPDATE", "1")
    assert verify_lock_transition("HEAD", "", cwd=str(repo), local=True, repo_url=remote.url) == []
    _stage(repo, {LOCK_PATH: remote.c3 + "\n"})
    assert verify_lock_transition("HEAD", "", cwd=str(repo), local=True, repo_url=remote.url) != []


def _committed_bump(tmp_path: Path, old: str, new: str, new_shim: str = "c1") -> tuple[Path, str, str]:
    """Lock bump that also syncs scripts/guard to consumer/guard at the new SHA (tag ``new_shim``)."""
    repo, base = _consumer(tmp_path, {LOCK_PATH: old + "\n", SHIM_PATH: _shim("c1")})
    return repo, base, _commit_files(repo, "chore: bump guard", {LOCK_PATH: new + "\n", SHIM_PATH: _shim(new_shim)})


def test_ci_descendant_annotated_tag_ok(tmp_path: Path, remote: Remote) -> None:
    repo, base, head = _committed_bump(tmp_path, remote.c1, remote.c2, "c2")
    assert verify_lock_transition(base, head, cwd=str(repo), local=False, repo_url=remote.url) == []
    assert released_descendant_error(remote.c1, remote.c2, repo_url=remote.url) is None
    assert released_descendant_error(None, remote.c1, repo_url=remote.url) is None


def test_downgrade_rejected(tmp_path: Path, remote: Remote) -> None:
    repo, base, head = _committed_bump(tmp_path, remote.c2, remote.c1)
    errs = verify_lock_transition(base, head, cwd=str(repo), local=False, repo_url=remote.url)
    assert len(errs) == 1 and "descendant" in errs[0]


def test_lightweight_tag_rejected(tmp_path: Path, remote: Remote) -> None:
    repo, base, head = _committed_bump(tmp_path, remote.c2, remote.c3, "c3")
    errs = verify_lock_transition(base, head, cwd=str(repo), local=False, repo_url=remote.url)
    assert len(errs) == 1 and "annotated" in errs[0]


def _tag_remote(tmp_path: Path, tags: list[tuple[str, str, bool]]) -> tuple[str, dict[str, str]]:
    """Bare stand-in: main c1 <- c2, side branch s1 <- c1; ``tags`` = (name, commit key in c1/c2/s1, annotated)."""
    work = tmp_path / "work"
    work.mkdir()
    for args in (["init", "-q"], ["config", "user.email", "guard@example.com"], ["config", "user.name", "Guard Test"]):
        _git(work, *args)
    c1 = _commit_files(work, "release 1", {"consumer/guard": _shim("c1")})
    _git(work, "checkout", "-q", "-b", "side")
    s1 = _commit_files(work, "side", {"side.txt": "s\n"})
    _git(work, "checkout", "-q", "-")
    c2 = _commit_files(work, "release 2", {"consumer/guard": _shim("c2")})
    shas = {"c1": c1, "c2": c2, "s1": s1}
    for name, key, annotated in tags:
        _git(work, "tag", *(["-a", "-m", name] if annotated else []), name, shas[key])
    bare = tmp_path / "remote.git"
    subprocess.run(["git", "clone", "--bare", "--quiet", str(work), str(bare)], check=True)
    return bare.as_uri(), shas


def test_release_accepts_annotated_v4_descendant(tmp_path: Path) -> None:
    url, shas = _tag_remote(tmp_path, [("v3.0.0", "c1", True), ("v4.0.0", "c2", True)])
    assert released_descendant_error(shas["c1"], shas["c2"], repo_url=url) is None


@pytest.mark.parametrize("tag", ["v4.0.0-rc1", "v4.0", "v5.0.0", "v3.3", "release-3.3.0"])
def test_release_rejects_prerelease_and_short_tags(tmp_path: Path, tag: str) -> None:
    url, shas = _tag_remote(tmp_path, [("v3.0.0", "c1", True), (tag, "c2", True)])
    err = released_descendant_error(shas["c1"], shas["c2"], repo_url=url)
    assert err is not None and "no annotated v3.x.y/v4.x.y release tag" in err


def test_release_rejects_lightweight_v4_tag(tmp_path: Path) -> None:
    url, shas = _tag_remote(tmp_path, [("v3.0.0", "c1", True), ("v4.0.0", "c2", False)])
    err = released_descendant_error(shas["c1"], shas["c2"], repo_url=url)
    assert err is not None and "annotated" in err


def test_release_rejects_v4_non_descendant(tmp_path: Path) -> None:
    url, shas = _tag_remote(tmp_path, [("v3.0.0", "c2", True), ("v4.0.0", "s1", True)])
    err = released_descendant_error(shas["c2"], shas["s1"], repo_url=url)
    assert err is not None and "is not a descendant of" in err


def test_release_tag_for_returns_lowest_semver_valid_tag(tmp_path: Path) -> None:
    tags = [("v4.0.0", "c2", True), ("v3.10.0", "c2", True), ("v3.9.0", "c2", True), ("v3.0.0-rc1", "c2", True), ("v3.0.5", "c2", False)]
    url, shas = _tag_remote(tmp_path, tags)
    git_dir = tmp_path / "remote.git"
    assert release_tag_for(str(git_dir), shas["c2"]) == "v3.9.0"
    assert release_tag_for(str(git_dir), shas["c1"]) is None


def test_lock_sha_absent_from_remote_rejected(tmp_path: Path, remote: Remote) -> None:
    repo, base, head = _committed_bump(tmp_path, remote.c1, ABSENT_SHA)
    errs = verify_lock_transition(base, head, cwd=str(repo), local=False, repo_url=remote.url)
    assert errs and f"{ABSENT_SHA} is not a commit in agent-ratchet" in errs[0]
    unreachable = (tmp_path / "no-such-remote.git").as_uri()
    reason = released_descendant_error(remote.c1, remote.c2, repo_url=unreachable)
    assert isinstance(reason, str) and reason
    assert verify_lock_transition(base, head, cwd=str(repo), local=False, repo_url=unreachable) != []


def test_bootstrap_manifest_to_lock_accepted(tmp_path: Path, remote: Remote) -> None:
    repo, base = _consumer(tmp_path, {LEGACY_MANIFEST_PATH: MANIFEST})
    _git(repo, "rm", "-q", LEGACY_MANIFEST_PATH)
    head = _commit_files(repo, "build: adopt guard.lock", {LOCK_PATH: remote.c1 + "\n", SHIM_PATH: _shim("c1")})
    assert verify_lock_transition(base, head, cwd=str(repo), local=False, repo_url=remote.url) == []
    _git(repo, "reset", "-q", "--hard", base)
    _git(repo, "rm", "-q", LEGACY_MANIFEST_PATH)
    bad_shim = _commit_files(repo, "build: adopt with foreign shim", {LOCK_PATH: remote.c1 + "\n", SHIM_PATH: _shim("forged")})
    assert verify_lock_transition(base, bad_shim, cwd=str(repo), local=False, repo_url=remote.url) == [
        f"scripts/guard does not match consumer/guard at agent-ratchet {remote.c1}"
    ]


def test_bootstrap_with_leftover_manifest_rejected(tmp_path: Path, remote: Remote) -> None:
    repo, _ = _consumer(tmp_path, {LEGACY_MANIFEST_PATH: MANIFEST})
    _stage(repo, {LOCK_PATH: remote.c1 + "\n", SHIM_PATH: _shim("c1")})
    for local in (True, False):
        assert verify_lock_transition("HEAD", "", cwd=str(repo), local=local, repo_url=remote.url) == [LEFTOVER_MSG]
    res = _run_baseline_guard(repo, "--enforce-policy-isolation", extra_env={"ALLOW_GUARD_LOCK_UPDATE": "1"})
    assert res.returncode == 2 and LEFTOVER_MSG in res.stderr


def test_shim_change_treated_like_lock_change(tmp_path: Path, remote: Remote, monkeypatch: pytest.MonkeyPatch) -> None:
    repo, base = _consumer(tmp_path, {LOCK_PATH: remote.c2 + "\n", SHIM_PATH: _shim("c1")})
    _stage(repo, {SHIM_PATH: _shim("c2")})
    assert verify_lock_transition("HEAD", "", cwd=str(repo), local=True, repo_url=remote.url) == [ENV_MSG]
    mismatch = f"scripts/guard does not match consumer/guard at agent-ratchet {remote.c2}"
    synced = _commit_files(repo, "build: sync shim", {})
    assert verify_lock_transition(base, synced, cwd=str(repo), local=False, repo_url=remote.url) == []
    forged = _commit_files(repo, "build: forge shim", {SHIM_PATH: "#!/bin/sh\nexit 0\n"})
    assert verify_lock_transition(synced, forged, cwd=str(repo), local=False, repo_url=remote.url) == [mismatch]
    _git(repo, "rm", "-q", SHIM_PATH)
    assert verify_lock_transition("HEAD", "", cwd=str(repo), local=False, repo_url=remote.url) == [mismatch]
    monkeypatch.setenv("ALLOW_GUARD_LOCK_UPDATE", "1")
    _git(repo, "reset", "-q", "--hard", synced)
    _stage(repo, {LOCK_PATH: remote.c1 + "\n", SHIM_PATH: _shim("c1")})
    errs = verify_lock_transition("HEAD", "", cwd=str(repo), local=True, repo_url=remote.url)
    assert len(errs) == 1 and "descendant" in errs[0]
    _git(repo, "reset", "-q", "--hard", base)
    _stage(repo, {LOCK_PATH: remote.c2 + "\n", SHIM_PATH: _shim("c3")})
    assert verify_lock_transition("HEAD", "", cwd=str(repo), local=True, repo_url=remote.url) == [mismatch]


def test_unreadable_canonical_shim_reported_distinctly(tmp_path: Path, remote: Remote, monkeypatch: pytest.MonkeyPatch) -> None:
    repo, base = _consumer(tmp_path, {LOCK_PATH: remote.c2 + "\n", SHIM_PATH: _shim("c1")})
    synced = _commit_files(repo, "build: sync shim", {SHIM_PATH: _shim("c2")})
    real_git = lock_policy._git

    def _lazy_fetch_fails(args: list[str], git_dir: str | None = None, cwd: str | None = None) -> subprocess.CompletedProcess[bytes]:
        if args[:2] == ["cat-file", "blob"]:
            return subprocess.CompletedProcess(args, 128, b"", b"fatal: could not fetch blob\n")
        return real_git(args, git_dir=git_dir, cwd=cwd)

    monkeypatch.setattr(lock_policy, "_git", _lazy_fetch_fails)
    lock_policy._remote_errors.cache_clear()
    try:
        errs = verify_lock_transition(base, synced, cwd=str(repo), local=False, repo_url=remote.url)
    finally:
        lock_policy._remote_errors.cache_clear()
    assert errs == [f"cannot read consumer/guard at agent-ratchet {remote.c2}: fatal: could not fetch blob"]


def test_lock_only_bump_requires_shim_to_match_new_sha(tmp_path: Path, remote: Remote) -> None:
    repo, base = _consumer(tmp_path, {LOCK_PATH: remote.c1 + "\n", SHIM_PATH: _shim("c1")})
    stale = _commit_files(repo, "chore: bump guard only", {LOCK_PATH: remote.c2 + "\n"})
    mismatch = f"scripts/guard does not match consumer/guard at agent-ratchet {remote.c2}"
    assert verify_lock_transition(base, stale, cwd=str(repo), local=False, repo_url=remote.url) == [mismatch]
    synced = _commit_files(repo, "build: sync shim", {SHIM_PATH: _shim("c2")})
    assert verify_lock_transition(base, synced, cwd=str(repo), local=False, repo_url=remote.url) == []


def test_shim_without_lock_rejected(tmp_path: Path, remote: Remote) -> None:
    repo, _ = _consumer(tmp_path, {})
    _stage(repo, {SHIM_PATH: _shim("c1")})
    errs = verify_lock_transition("HEAD", "", cwd=str(repo), local=False, repo_url=remote.url)
    assert len(errs) == 1 and errs[0].startswith("scripts/guard does not match consumer/guard at agent-ratchet")


def test_locally_committed_bump_does_not_block_later_commits(tmp_path: Path, remote: Remote) -> None:
    repo, base, _ = _committed_bump(tmp_path, remote.c1, remote.c2, "c2")
    _git(repo, "update-ref", "refs/remotes/origin/main", base)
    _stage(repo, {"src/app.py": "A = 3\n"})
    assert staged_lock_errors(str(repo), repo_url=remote.url) == []
    _stage(repo, {LOCK_PATH: remote.c1 + "\n", SHIM_PATH: _shim("c1")})
    assert staged_lock_errors(str(repo), repo_url=remote.url) == [ENV_MSG]


def test_staged_check_judges_index_against_trusted_base(tmp_path: Path, remote: Remote) -> None:
    repo, base, _ = _committed_bump(tmp_path, remote.c2, remote.c1)
    _git(repo, "update-ref", "refs/remotes/origin/main", base)
    _stage(repo, {"src/app.py": "A = 3\n"})
    errs = staged_lock_errors(str(repo), repo_url=remote.url)
    assert len(errs) == 1 and "descendant" in errs[0]


def test_ci_lock_check_requires_trusted_base(tmp_path: Path) -> None:
    origin, _ = _consumer(tmp_path / "origin", {LOCK_PATH: "1" * 40 + "\n"})
    clone = tmp_path / "clone"
    subprocess.run(["git", "clone", "-q", str(origin), str(clone)], check=True)
    _git(clone, "config", "core.hooksPath", "/dev/null")
    _git(clone, "remote", "remove", "origin")
    res = _run_baseline_guard(clone, "--require-base-ref")
    assert res.returncode == 2, res.stderr + res.stdout
    assert "--require-base-ref" in res.stderr
    with pytest.raises(GuardAnalysisError):
        staged_lock_errors(str(clone), require_base_ref=True)
    assert _run_baseline_guard(clone).returncode == 0


def test_guard_lock_is_protected_governance_path(tmp_path: Path) -> None:
    assert is_protected_governance_path(LOCK_PATH) and is_protected_governance_path(SHIM_PATH)
    repo, base = _consumer(tmp_path, {LOCK_PATH: "1" * 40 + "\n"})
    head = _commit_files(repo, "chore: mixed", {LOCK_PATH: "2" * 40 + "\n", "src/x.py": "X = 1\n"})
    res = _run_baseline_guard(repo, "--require-base-ref", "--enforce-policy-isolation", "--commit-range", f"{base}..{head}")
    assert res.returncode == 1, res.stderr + res.stdout
    assert "Policy isolation violation" in res.stderr and LOCK_PATH in res.stderr


def test_case_variants_of_pin_files_are_governance() -> None:
    for variant in ("Guard.lock", "GUARD.LOCK", "Scripts/Guard", "scripts/GUARD"):
        assert is_protected_governance_path(variant), variant
    assert not is_protected_governance_path("Scripts/Audit/guard_manifest.json")
    assert not is_protected_governance_path("guard.lock.bak")


def test_malformed_staged_lock_is_analysis_error(tmp_path: Path) -> None:
    repo, _ = _consumer(tmp_path, {})
    _stage(repo, {LOCK_PATH: "not-a-sha\n"})
    for runner in (_run_scanner, _run_baseline_guard):
        assert runner(repo, "--staged-only").returncode == 2


def test_legacy_manifest_unchanged_without_lock_ok(tmp_path: Path) -> None:
    repo, base = _consumer(tmp_path, {LEGACY_MANIFEST_PATH: MANIFEST})
    _stage(repo, {"src/app.py": "A = 2\n"})
    assert verify_lock_transition("HEAD", "", cwd=str(repo), local=True) == []
    assert _run_scanner(repo, "--staged-only").returncode == 0
    head = _commit_files(repo, "feat: app", {})
    assert _run_baseline_guard(repo, "--require-base-ref", "--enforce-policy-isolation", "--commit-range", f"{base}..{head}").returncode == 0


def test_legacy_manifest_deleted_without_lock_rejected(tmp_path: Path) -> None:
    repo, _ = _consumer(tmp_path, {LEGACY_MANIFEST_PATH: MANIFEST})
    _git(repo, "rm", "-q", LEGACY_MANIFEST_PATH)
    for local in (True, False):
        assert verify_lock_transition("HEAD", "", cwd=str(repo), local=local) == [LEGACY_DELETED_MSG]
    res = _run_scanner(repo, "--staged-only")
    assert res.returncode == 2 and LEGACY_DELETED_MSG in res.stderr


def test_legacy_manifest_modified_without_lock_rejected(tmp_path: Path) -> None:
    repo, base = _consumer(tmp_path, {LEGACY_MANIFEST_PATH: MANIFEST})
    head = _commit_files(repo, "chore: edit manifest", {LEGACY_MANIFEST_PATH: MANIFEST.replace("2.3.3", "2.3.4")})
    assert verify_lock_transition(base, head, cwd=str(repo), local=False) == [LEGACY_CHANGED_MSG]
    res = _run_scanner(repo, "--commit-range", f"{base}..{head}")
    assert res.returncode == 1 and LEGACY_CHANGED_MSG in res.stderr


def test_baseline_integrity_help_runs_argparse_outside_a_repo(tmp_path: Path) -> None:
    res = _run_baseline_guard(tmp_path, "--help")
    assert res.returncode == 0, res.stderr
    assert "--require-base-ref" in res.stdout


# --- Fix round 1 -------------------------------------------------------------


def _detached_clone(tmp_path: Path, files: dict[str, str]) -> tuple[Path, str]:
    origin, base = _consumer(tmp_path / "origin", files)
    clone = tmp_path / "clone"
    subprocess.run(["git", "clone", "-q", str(origin), str(clone)], check=True)
    _git(clone, "config", "core.hooksPath", "/dev/null")
    _git(clone, "remote", "remove", "origin")
    return clone, base


def test_require_base_ref_without_pin_keeps_2_3_3_behaviour(tmp_path: Path) -> None:
    clone, _ = _detached_clone(tmp_path, {})
    assert staged_lock_errors(str(clone), require_base_ref=True) == []
    for args in (("--require-base-ref",), ("--require-base-ref", "--staged-only")):
        res = _run_baseline_guard(clone, *args)
        assert res.returncode == 0, res.stderr + res.stdout
        assert LOCK_PATH not in res.stderr
    _stage(clone, {SHIM_PATH: _shim("c1")})
    with pytest.raises(GuardAnalysisError):
        staged_lock_errors(str(clone), require_base_ref=True)


def test_trusted_base_follows_ci_candidates(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    clone, base = _detached_clone(tmp_path, {LOCK_PATH: "1" * 40 + "\n"})
    _git(clone, "update-ref", "refs/remotes/origin/release", base)
    res = _run_baseline_guard(clone, "--require-base-ref", extra_env={"CI_MERGE_REQUEST_TARGET_BRANCH_NAME": "release"})
    assert res.returncode == 0, res.stderr + res.stdout
    _git(clone, "update-ref", "-d", "refs/remotes/origin/release")
    res = _run_baseline_guard(clone, "--require-base-ref", extra_env={"CI_COMMIT_BEFORE_SHA": base})
    assert res.returncode == 0, res.stderr + res.stdout
    monkeypatch.setenv("CI_COMMIT_BEFORE_SHA", base)
    assert staged_lock_errors(str(clone), require_base_ref=True) == []


def _symlink(repo: Path, rel: str, target: str) -> None:
    path = repo / rel
    if path.exists() or path.is_symlink():
        path.unlink()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.symlink_to(target)


def test_symlinked_lock_in_commit_range_rejected(tmp_path: Path, remote: Remote) -> None:
    repo, base = _consumer(tmp_path, {LOCK_PATH: remote.c1 + "\n", SHIM_PATH: _shim("c1")})
    _symlink(repo, LOCK_PATH, remote.c1)
    _write_files(repo, {remote.c1: remote.c3 + "\n"})
    _git(repo, "add", LOCK_PATH, remote.c1)
    _git(repo, "commit", "-q", "-m", "chore: link lock")
    msg = "guard.lock must be a regular file (mode 100644), not mode 120000"
    assert verify_lock_transition(base, "HEAD", cwd=str(repo), local=False, repo_url=remote.url) == [msg]
    res = _run_scanner(repo, "--commit-range", f"{base}..HEAD")
    assert res.returncode == 1 and msg in res.stderr


def test_symlinked_lock_in_index_rejected(tmp_path: Path, remote: Remote) -> None:
    repo, _ = _consumer(tmp_path, {LOCK_PATH: remote.c1 + "\n", SHIM_PATH: _shim("c1")})
    _symlink(repo, LOCK_PATH, remote.c1)
    _write_files(repo, {remote.c1: remote.c3 + "\n"})
    _git(repo, "add", LOCK_PATH, remote.c1)
    msg = "guard.lock must be a regular file (mode 100644), not mode 120000"
    for local in (True, False):
        assert verify_lock_transition("HEAD", "", cwd=str(repo), local=local, repo_url=remote.url) == [msg]
    assert verify_lock_transition("HEAD", "WORKTREE", cwd=str(repo), local=True, repo_url=remote.url) == [msg]
    res = _run_scanner(repo, "--staged-only")
    assert res.returncode == 2 and msg in res.stderr


def test_symlinked_shim_rejected(tmp_path: Path, remote: Remote) -> None:
    repo, base = _consumer(tmp_path, {LOCK_PATH: remote.c1 + "\n", SHIM_PATH: _shim("c1")})
    _write_files(repo, {"tools/guard": _shim("c1")})
    _symlink(repo, SHIM_PATH, "../tools/guard")
    _git(repo, "add", SHIM_PATH, "tools/guard")
    msg = "scripts/guard must be a regular file (mode 100644 or 100755), not mode 120000"
    assert verify_lock_transition("HEAD", "", cwd=str(repo), local=False, repo_url=remote.url) == [msg]
    head = _commit_files(repo, "chore: link shim", {})
    assert verify_lock_transition(base, head, cwd=str(repo), local=False, repo_url=remote.url) == [msg]


def test_mode_only_change_counts_as_change(tmp_path: Path, remote: Remote) -> None:
    repo, base = _consumer(tmp_path, {LOCK_PATH: remote.c1 + "\n", SHIM_PATH: _shim("c1")})
    _git(repo, "update-index", "--chmod=+x", SHIM_PATH)
    assert verify_lock_transition("HEAD", "", cwd=str(repo), local=True, repo_url=remote.url) == [ENV_MSG]
    head = _commit_files(repo, "chore: chmod shim", {})
    unreachable = (tmp_path / "missing.git").as_uri()
    assert verify_lock_transition(base, head, cwd=str(repo), local=False, repo_url=unreachable) != []
    assert verify_lock_transition(base, head, cwd=str(repo), local=False, repo_url=remote.url) == []
    _git(repo, "update-index", "--chmod=+x", LOCK_PATH)
    assert verify_lock_transition("HEAD", "", cwd=str(repo), local=False, repo_url=remote.url) == [
        "guard.lock must be a regular file (mode 100644), not mode 100755"
    ]


def test_commit_range_x_z_x_judges_every_hop(tmp_path: Path, remote: Remote, monkeypatch: pytest.MonkeyPatch) -> None:
    """X -> unreleased Z -> X nets to no change, so only the per-commit hops can reject it (T4-c)."""
    repo, base = _consumer(tmp_path, {LOCK_PATH: remote.c1 + "\n", SHIM_PATH: _shim("c1")})
    hop_z = _commit_files(repo, "chore: bump to unreleased", {LOCK_PATH: remote.c3 + "\n"})
    head = _commit_files(repo, "chore: back to release", {LOCK_PATH: remote.c1 + "\n"})
    judged: list[tuple[str | None, str]] = []

    def _recording(base_prefix: str | None, target_prefix: str, cwd: str | None = None, *, local: bool) -> list[str]:
        judged.append((base_prefix, target_prefix))
        return verify_lock_transition(base_prefix, target_prefix, cwd=cwd, local=local, repo_url=remote.url)

    monkeypatch.setattr(ai_slop_scanner, "verify_lock_transition", _recording)
    monkeypatch.setattr(test_baseline_integrity, "verify_lock_transition", _recording)
    assert verify_lock_transition(base, head, cwd=str(repo), local=False, repo_url=remote.url) == []

    errors = [v.message for v in ai_slop_scanner._evaluate_commit_range(f"{base}..{head}", cwd=str(repo)) if v.file == LOCK_PATH]
    assert {(base, hop_z), (hop_z, head), (base, head)} <= set(judged)
    assert any(remote.c3 in e and "annotated" in e for e in errors), errors
    assert any(remote.c3 in e and "descendant" in e for e in errors), errors

    judged.clear()
    monkeypatch.chdir(repo)
    ok, msgs = test_baseline_integrity._evaluate_commit_range(f"{base}..{head}", False, None)
    assert not ok and (base, hop_z) in judged
    assert any(remote.c3 in m and "annotated" in m for m in msgs), msgs


def _invalid_base_lock_msg(mode: str) -> str:
    return f"guard.lock in the base is not a regular file (mode {mode}); a lock transition cannot be verified"


def test_symlinked_base_lock_fails_closed(tmp_path: Path, remote: Remote, monkeypatch: pytest.MonkeyPatch) -> None:
    repo, _ = _consumer(tmp_path, {SHIM_PATH: _shim("c1"), remote.c1: remote.c2 + "\n"})
    _symlink(repo, LOCK_PATH, remote.c1)
    _git(repo, "add", LOCK_PATH)
    base = _commit_files(repo, "chore: link lock", {})
    _git(repo, "rm", "-q", "--cached", LOCK_PATH)
    (repo / LOCK_PATH).unlink()
    head = _commit_files(repo, "chore: regular lock", {LOCK_PATH: remote.c2 + "\n"})
    assert verify_lock_transition(base, head, cwd=str(repo), local=False, repo_url=remote.url) == [_invalid_base_lock_msg("120000")]
    monkeypatch.setenv("ALLOW_GUARD_LOCK_UPDATE", "1")
    _stage(repo, {"src/app.py": "A = 2\n"})
    assert verify_lock_transition(base, "", cwd=str(repo), local=True, repo_url=remote.url) == [_invalid_base_lock_msg("120000")]


def test_executable_base_lock_fails_closed(tmp_path: Path, remote: Remote) -> None:
    repo, _ = _consumer(tmp_path, {LOCK_PATH: remote.c1 + "\n", SHIM_PATH: _shim("c1")})
    _git(repo, "update-index", "--chmod=+x", LOCK_PATH)
    base = _commit_files(repo, "chore: chmod lock", {})
    _git(repo, "update-index", "--chmod=-x", LOCK_PATH)
    head = _commit_files(repo, "chore: bump guard", {LOCK_PATH: remote.c2 + "\n"})
    assert verify_lock_transition(base, head, cwd=str(repo), local=False, repo_url=remote.url) == [_invalid_base_lock_msg("100755")]
    unreachable = (tmp_path / "missing.git").as_uri()
    assert verify_lock_transition(head, head, cwd=str(repo), local=False, repo_url=unreachable) == []


def test_remote_checks_ignore_inherited_git_env(tmp_path: Path, remote: Remote, monkeypatch: pytest.MonkeyPatch) -> None:
    repo, _ = _consumer(tmp_path, {})
    _git(repo, "fetch", "-q", remote.url, remote.c3)
    _git(repo, "tag", "-a", "v3.9.9", "-m", "local", remote.c3)
    bogus = (tmp_path / "bogus.git").as_uri()
    monkeypatch.setenv("GIT_DIR", str(repo / ".git"))
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", f"url.{bogus}.insteadOf")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", remote.url)
    lock_policy._remote_errors.cache_clear()
    try:
        assert released_descendant_error(remote.c1, remote.c2, repo_url=remote.url) is None
        reason = released_descendant_error(remote.c2, remote.c3, repo_url=remote.url)
        assert reason is not None and "annotated" in reason
    finally:
        lock_policy._remote_errors.cache_clear()


def test_staged_check_uses_merge_base_with_trusted_ref(tmp_path: Path, remote: Remote, monkeypatch: pytest.MonkeyPatch) -> None:
    repo, base = _consumer(tmp_path, {LOCK_PATH: remote.c1 + "\n", SHIM_PATH: _shim("c1")})
    bumped = _commit_files(repo, "chore: bump guard", {LOCK_PATH: remote.c2 + "\n", SHIM_PATH: _shim("c2")})
    _git(repo, "update-ref", "refs/remotes/origin/main", bumped)
    _git(repo, "reset", "-q", "--hard", base)
    _stage(repo, {"src/app.py": "A = 3\n"})

    def _no_clone(*_args: object) -> tuple[str | None, str | None]:
        raise AssertionError("no agent-ratchet clone expected for an unchanged lock")

    monkeypatch.setattr(lock_policy, "_clone", _no_clone)
    lock_policy._remote_errors.cache_clear()
    assert staged_lock_errors(str(repo), repo_url=remote.url) == []
