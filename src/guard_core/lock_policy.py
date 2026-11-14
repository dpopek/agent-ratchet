#!/usr/bin/env python3
"""Guard Core 3 pin protection: ``guard.lock`` and ``scripts/guard`` transition rules (successor of the 2.x SHA manifest)."""

from __future__ import annotations

from functools import lru_cache
import os
import re
import subprocess
import sys
import tempfile

from guard_core.git_guard_io import GuardAnalysisError, _read_ref_file_bytes, default_remote_refs

GUARD_CORE_URL: str = "https://github.com/dpopek/guard-core"
LOCK_PATH = "guard.lock"
SHIM_PATH = "scripts/guard"
LEGACY_MANIFEST_PATH = "scripts/audit/guard_manifest.json"
CANONICAL_SHIM_PATH = "consumer/guard"
LOCK_UPDATE_ENV = "ALLOW_GUARD_LOCK_UPDATE"
RELEASE_TAG_PATTERN = "refs/tags/v3.*"

_LOCK_RE = re.compile(rb"\A[0-9a-f]{40}\n?\Z")
_SHA_RE = re.compile(r"\A[0-9a-f]{40}\Z")
_GIT_TIMEOUT_S = 120
_GIT_ENV = {"LC_ALL": "C", "GIT_TERMINAL_PROMPT": "0"}

ENV_REQUIRED_MSG = f"{LOCK_PATH}/{SHIM_PATH} change requires {LOCK_UPDATE_ENV}=1"
LOCK_DELETED_MSG = f"{LOCK_PATH} was deleted"
LEFTOVER_MANIFEST_MSG = f"remove {LEGACY_MANIFEST_PATH} when adopting {LOCK_PATH}"
LEGACY_DELETED_MSG = f"{LEGACY_MANIFEST_PATH} was deleted without adopting {LOCK_PATH}"
LEGACY_CHANGED_MSG = f"{LEGACY_MANIFEST_PATH} changed; Guard Core 3 is pinned by {LOCK_PATH}"


def _shim_mismatch_msg(sha: str | None) -> str:
    return f"{SHIM_PATH} does not match {CANONICAL_SHIM_PATH} at guard-core {sha or '(no guard.lock)'}"


def lock_check_is_local(target_prefix: str | None) -> bool:
    """The operator env gate applies to uncommitted targets (index or worktree); committed history is judged by the remote alone."""
    return not target_prefix or target_prefix == "WORKTREE"


def _snapshot_bytes(ref_prefix: str | None, rel_path: str, cwd: str | None) -> bytes | None:
    return None if ref_prefix is None else _read_ref_file_bytes(ref_prefix, rel_path, cwd=cwd)


def read_lock(ref_prefix: str, cwd: str | None = None) -> str | None:
    raw = _read_ref_file_bytes(ref_prefix, LOCK_PATH, cwd=cwd)
    if raw is None:
        return None
    if not _LOCK_RE.match(raw):
        raise GuardAnalysisError(f"Malformed {LOCK_PATH} at {ref_prefix or 'INDEX'}: expected 40 lowercase hex characters and at most one trailing newline")
    return raw[:40].decode("ascii")


def _git(args: list[str], cwd: str | None = None) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, timeout=_GIT_TIMEOUT_S, env={**os.environ, **_GIT_ENV})


def _clone(repo_url: str, dest: str) -> tuple[str | None, str | None]:
    """Bare clone, partial when the server allows it, else full; returns (git_dir, None) or (None, failure reason)."""
    reason = ""
    for name, extra in (("partial.git", ["--filter=blob:none"]), ("full.git", [])):
        res = _git(["clone", "--bare", "--quiet", *extra, "--", repo_url, f"{dest}/{name}"])
        if res.returncode == 0:
            return f"{dest}/{name}", None
        reason = res.stderr.decode("utf-8", errors="replace").strip()
    return None, f"cannot clone guard-core from {repo_url}: {reason}"


def _release_error(git_dir: str, old_sha: str | None, new_sha: str) -> str | None:
    if _git(["cat-file", "-e", f"{new_sha}^{{commit}}"], cwd=git_dir).returncode != 0:
        return f"{LOCK_PATH} SHA {new_sha} is not a commit in guard-core"
    if old_sha is not None:
        rc = _git(["merge-base", "--is-ancestor", old_sha, new_sha], cwd=git_dir).returncode
        if rc != 0:
            return f"{LOCK_PATH} {new_sha} is not a descendant of {old_sha} in guard-core"
    refs = _git(["for-each-ref", "--format=%(refname)", RELEASE_TAG_PATTERN], cwd=git_dir)
    if refs.returncode != 0:
        return f"cannot list guard-core release tags: {refs.stderr.decode('utf-8', errors='replace').strip()}"
    for ref in refs.stdout.decode("utf-8", errors="replace").split():
        if _git(["cat-file", "-t", ref], cwd=git_dir).stdout.strip() != b"tag":
            continue
        peeled = _git(["rev-parse", "--verify", "-q", f"{ref}^{{commit}}"], cwd=git_dir)
        if peeled.returncode == 0 and peeled.stdout.strip().decode("ascii", errors="replace") == new_sha:
            return None
    return f"{LOCK_PATH} {new_sha} carries no annotated v3.x.y release tag in guard-core"


def _shim_error(git_dir: str, sha: str, shim: bytes | None) -> str | None:
    canonical = _git(["cat-file", "blob", f"{sha}:{CANONICAL_SHIM_PATH}"], cwd=git_dir)
    if canonical.returncode != 0 or shim is None or canonical.stdout != shim:
        return _shim_mismatch_msg(sha)
    return None


@lru_cache(maxsize=32)
def _remote_errors(repo_url: str, old_sha: str | None, new_sha: str, check_release: bool, shim: bytes | None, check_shim: bool) -> tuple[str, ...]:
    """Release (descendant + annotated tag) and shim checks against one temporary clone; any failure is a reason, never an exception."""
    if not _SHA_RE.match(new_sha) or (old_sha is not None and not _SHA_RE.match(old_sha)):
        return (f"invalid guard-core SHA ({old_sha!r} -> {new_sha!r})",)
    try:
        with tempfile.TemporaryDirectory(prefix="guard_core_clone_") as tmp:
            git_dir, clone_err = _clone(repo_url, tmp)
            if git_dir is None:
                return (clone_err or f"cannot clone guard-core from {repo_url}",)
            errs = [_release_error(git_dir, old_sha, new_sha) if check_release else None, _shim_error(git_dir, new_sha, shim) if check_shim else None]
            return tuple(e for e in errs if e is not None)
    except (OSError, subprocess.SubprocessError) as exc:
        return (f"cannot verify guard-core {new_sha} against {repo_url}: {exc}",)


def released_descendant_error(old_sha: str | None, new_sha: str, repo_url: str = GUARD_CORE_URL) -> str | None:
    errs = _remote_errors(repo_url, old_sha, new_sha, True, None, False)
    return errs[0] if errs else None


def _legacy_manifest_errors(base_manifest: bytes | None, target_manifest: bytes | None) -> list[str]:
    if base_manifest is None:
        return []
    if target_manifest is None:
        return [LEGACY_DELETED_MSG]
    return [LEGACY_CHANGED_MSG] if target_manifest != base_manifest else []


def verify_lock_transition(
    base_prefix: str | None, target_prefix: str, cwd: str | None = None, *, local: bool, repo_url: str = GUARD_CORE_URL
) -> list[str]:
    base_lock = read_lock(base_prefix, cwd=cwd) if base_prefix is not None else None
    target_lock = read_lock(target_prefix, cwd=cwd)
    base_shim, target_shim = _snapshot_bytes(base_prefix, SHIM_PATH, cwd), _snapshot_bytes(target_prefix, SHIM_PATH, cwd)
    target_manifest = _snapshot_bytes(target_prefix, LEGACY_MANIFEST_PATH, cwd)
    lock_changed, shim_changed = base_lock != target_lock, base_shim != target_shim
    if base_lock is not None and target_lock is None:
        return [LOCK_DELETED_MSG]
    if base_lock is None and target_lock is not None and target_manifest is not None:
        return [LEFTOVER_MANIFEST_MSG]
    if target_lock is None:
        legacy = _legacy_manifest_errors(_snapshot_bytes(base_prefix, LEGACY_MANIFEST_PATH, cwd), target_manifest)
        if legacy:
            return legacy
    if not (lock_changed or shim_changed):
        return []
    if local and os.environ.get(LOCK_UPDATE_ENV) != "1":
        return [ENV_REQUIRED_MSG]
    if target_lock is None:
        return [_shim_mismatch_msg(None)]
    return list(_remote_errors(repo_url, base_lock, target_lock, lock_changed, target_shim, shim_changed))


def staged_lock_errors(cwd: str | None = None, *, require_base_ref: bool = False, repo_url: str = GUARD_CORE_URL) -> list[str]:
    """Pre-commit check of the index: trusted base -> index by the remote alone, then HEAD -> index with the operator env gate."""
    trusted = default_remote_refs(cwd)
    if not trusted and require_base_ref:
        raise GuardAnalysisError(f"--require-base-ref: no origin/<default> ref to judge {LOCK_PATH} against")
    errs = verify_lock_transition(trusted[0], "", cwd=cwd, local=False, repo_url=repo_url) if trusted else []
    return errs or verify_lock_transition("HEAD", "", cwd=cwd, local=True, repo_url=repo_url)


def check_staged_lock(cwd: str | None = None, *, require_base_ref: bool = False) -> int | None:
    """CLI wrapper: exit code 2 on any pin violation or analysis error, None when the index may proceed."""
    try:
        errs = staged_lock_errors(cwd, require_base_ref=require_base_ref)
    except GuardAnalysisError as exc:
        print(f"ERROR: [guard_analysis_error] {exc}", file=sys.stderr)
        return 2
    if errs:
        print(f"ERROR: {errs[0]}", file=sys.stderr)
        return 2
    return None
