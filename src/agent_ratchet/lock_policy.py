#!/usr/bin/env python3
"""agent-ratchet 3 pin protection: ``guard.lock`` and ``scripts/guard`` transition rules (successor of the 2.x SHA manifest)."""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
from typing import Iterable, Literal

from agent_ratchet.git_guard_io import GuardAnalysisError, _git_out, _read_ref_file_bytes, head_commit_exists, trusted_base_candidates

GUARD_CORE_URL: str = "https://github.com/dpopek/agent-ratchet"
LOCK_PATH = "guard.lock"
SHIM_PATH = "scripts/guard"
LEGACY_MANIFEST_PATH = "scripts/audit/guard_manifest.json"
CANONICAL_SHIM_PATH = "consumer/guard"
LOCK_UPDATE_ENV = "ALLOW_GUARD_LOCK_UPDATE"
RELEASE_TAG_PATTERNS: tuple[str, ...] = ("refs/tags/v3.*", "refs/tags/v4.*")
RELEASE_TAG_PATTERN = RELEASE_TAG_PATTERNS[0]  # deprecated alias, removed in 4.0
RELEASE_TAG_RE = re.compile(r"\Av(3|4)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z")

_LOCK_RE = re.compile(rb"\A([0-9a-f]{40})(?:\nEXTRAS=(none|php|magento))?\n?\Z")
_SHA_RE = re.compile(r"\A[0-9a-f]{40}\Z")
_GIT_TIMEOUT_S = 120
_ISOLATED_GIT_ENV = {"LC_ALL": "C", "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull}
_ALLOWED_MODES: dict[str, tuple[str, ...]] = {LOCK_PATH: ("100644",), SHIM_PATH: ("100644", "100755")}

ENV_REQUIRED_MSG = f"{LOCK_PATH}/{SHIM_PATH} change requires {LOCK_UPDATE_ENV}=1"
LOCK_DELETED_MSG = f"{LOCK_PATH} was deleted"
LEFTOVER_MANIFEST_MSG = f"remove {LEGACY_MANIFEST_PATH} when adopting {LOCK_PATH}"
LEGACY_DELETED_MSG = f"{LEGACY_MANIFEST_PATH} was deleted without adopting {LOCK_PATH}"
LEGACY_CHANGED_MSG = f"{LEGACY_MANIFEST_PATH} changed; agent-ratchet 3 is pinned by {LOCK_PATH}"


def _shim_mismatch_msg(sha: str | None) -> str:
    return f"{SHIM_PATH} does not match {CANONICAL_SHIM_PATH} at agent-ratchet {sha or '(no guard.lock)'}"


def _mode_msg(rel_path: str, mode: str) -> str:
    return f"{rel_path} must be a regular file (mode {' or '.join(_ALLOWED_MODES[rel_path])}), not mode {mode}"


def lock_check_is_local(target_prefix: str | None) -> bool:
    """The operator env gate applies to uncommitted targets (index or worktree); committed history is judged by the remote alone."""
    return not target_prefix or target_prefix == "WORKTREE"


def _snapshot_bytes(ref_prefix: str | None, rel_path: str, cwd: str | None) -> bytes | None:
    return None if ref_prefix is None else _read_ref_file_bytes(ref_prefix, rel_path, cwd=cwd)


def _worktree_mode(path: Path) -> str | None:
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(st.st_mode):
        return "120000"
    if stat.S_ISREG(st.st_mode):
        return "100755" if st.st_mode & 0o111 else "100644"
    return "040000" if stat.S_ISDIR(st.st_mode) else oct(stat.S_IFMT(st.st_mode))[2:]


def entry_mode(ref_prefix: str | None, rel_path: str, cwd: str | None = None) -> str | None:
    """Git tree-entry mode of ``rel_path`` in a commit, the index (``""``) or the worktree; None when absent."""
    if ref_prefix is None or (ref_prefix == "HEAD" and not head_commit_exists(cwd)):
        return None
    if ref_prefix == "WORKTREE":
        return _worktree_mode((Path(cwd) if cwd else Path(".")) / rel_path)
    if ref_prefix == "":
        cmd = ["git", "ls-files", "-s", "-z", "--", f":(top,literal){rel_path}"]
    else:
        cmd = ["git", "ls-tree", "-z", "--full-tree", ref_prefix, "--", rel_path]
    res = subprocess.run(cmd, cwd=cwd, capture_output=True)
    if res.returncode != 0:
        raise GuardAnalysisError(f"Cannot read the tree entry of {rel_path} at {ref_prefix or 'INDEX'}: {res.stderr.decode('utf-8', errors='replace').strip()}")
    for record in res.stdout.split(b"\0"):
        meta, _, path = record.partition(b"\t")
        if meta:
            return meta.split(b" ", 1)[0].decode("ascii") if path.decode("utf-8", errors="replace") == rel_path else "040000"
    return None


@dataclass(frozen=True)
class LockSpec:
    sha: str
    extras: Literal["none", "php", "magento"] = "none"


def read_lock_spec(ref_prefix: str, cwd: str | None = None) -> LockSpec | None:
    raw = _read_ref_file_bytes(ref_prefix, LOCK_PATH, cwd=cwd)
    if raw is None:
        return None
    match = _LOCK_RE.match(raw)
    if not match:
        raise GuardAnalysisError(
            f"Malformed {LOCK_PATH} at {ref_prefix or 'INDEX'}: expected 40 lowercase hex characters, an optional EXTRAS=none|php|magento line and at most one trailing newline"
        )
    return LockSpec(match.group(1).decode("ascii"), (match.group(2) or b"none").decode("ascii"))  # type: ignore[arg-type]


def read_lock(ref_prefix: str, cwd: str | None = None) -> str | None:
    spec = read_lock_spec(ref_prefix, cwd=cwd)
    return None if spec is None else spec.sha


def _isolated_env() -> dict[str, str]:
    """Environment for agent-ratchet clone calls: no inherited GIT_* (hook GIT_DIR, GIT_CONFIG_* insteadOf), no system/global config."""
    return {**{k: v for k, v in os.environ.items() if not k.startswith("GIT_")}, **_ISOLATED_GIT_ENV}


def _git(args: list[str], git_dir: str | None = None, cwd: str | None = None) -> subprocess.CompletedProcess[bytes]:
    prefix = [f"--git-dir={git_dir}"] if git_dir else []
    return subprocess.run(["git", *prefix, *args], cwd=cwd or git_dir, capture_output=True, timeout=_GIT_TIMEOUT_S, env=_isolated_env())


def _clone(repo_url: str, dest: str) -> tuple[str | None, str | None]:
    """Bare clone, partial when the server allows it, else full; returns (git_dir, None) or (None, failure reason)."""
    reason = ""
    for name, extra in (("partial.git", ["--filter=blob:none"]), ("full.git", [])):
        res = _git(["clone", "--bare", "--quiet", *extra, "--", repo_url, f"{dest}/{name}"], cwd=dest)
        if res.returncode == 0:
            return f"{dest}/{name}", None
        reason = res.stderr.decode("utf-8", errors="replace").strip()
    return None, f"cannot clone agent-ratchet from {repo_url}: {reason}"


class ReleaseTagListError(Exception):
    """Release tags of agent-ratchet could not be listed (fail closed: never read as "no tag")."""


def release_tag_for(git_dir: str, sha: str) -> str | None:
    """Name of the lowest-SemVer annotated v3/v4 release tag that peels to ``sha``; None when there is none.

    Raises ReleaseTagListError when the tags cannot be listed.
    """
    refs = _git(["for-each-ref", "--format=%(refname)", *RELEASE_TAG_PATTERNS], git_dir=git_dir)
    if refs.returncode != 0:
        raise ReleaseTagListError(refs.stderr.decode("utf-8", errors="replace").strip())
    found: list[tuple[tuple[int, ...], str]] = []
    for ref in refs.stdout.decode("utf-8", errors="replace").split():
        name = ref.removeprefix("refs/tags/")
        match = RELEASE_TAG_RE.match(name)
        if not match or _git(["cat-file", "-t", ref], git_dir=git_dir).stdout.strip() != b"tag":
            continue
        peeled = _git(["rev-parse", "--verify", "-q", f"{ref}^{{commit}}"], git_dir=git_dir)
        if peeled.returncode == 0 and peeled.stdout.strip().decode("ascii", errors="replace") == sha:
            found.append((tuple(int(g) for g in match.groups()), name))
    return min(found)[1] if found else None


def _release_error(git_dir: str, old_sha: str | None, new_sha: str, extras: str = "none") -> str | None:
    if _git(["cat-file", "-e", f"{new_sha}^{{commit}}"], git_dir=git_dir).returncode != 0:
        return f"{LOCK_PATH} SHA {new_sha} is not a commit in agent-ratchet"
    if old_sha is not None:
        rc = _git(["merge-base", "--is-ancestor", old_sha, new_sha], git_dir=git_dir).returncode
        if rc != 0:
            return f"{LOCK_PATH} {new_sha} is not a descendant of {old_sha} in agent-ratchet"
    try:
        tag = release_tag_for(git_dir, new_sha)
    except ReleaseTagListError as exc:
        return f"cannot list agent-ratchet release tags: {exc}"
    if not tag:
        return f"{LOCK_PATH}: no annotated v3.x.y/v4.x.y release tag peels to {new_sha} in agent-ratchet"
    if extras != "none" and not tag.startswith("v4."):
        return f"{LOCK_PATH}: EXTRAS={extras} requires a v4.x.y release, but {new_sha} is released as {tag}"
    return None


def _shim_error(git_dir: str, sha: str, shim: bytes | None) -> str | None:
    canonical = _git(["cat-file", "blob", f"{sha}:{CANONICAL_SHIM_PATH}"], git_dir=git_dir)
    if canonical.returncode != 0:
        return f"cannot read {CANONICAL_SHIM_PATH} at agent-ratchet {sha}: {canonical.stderr.decode('utf-8', errors='replace').strip()}"
    if shim is None or canonical.stdout != shim:
        return _shim_mismatch_msg(sha)
    return None


@lru_cache(maxsize=32)
def _remote_errors(
    repo_url: str, old_sha: str | None, new_sha: str, check_release: bool, shim: bytes | None, check_shim: bool, extras: str = "none"
) -> tuple[str, ...]:
    """Release (descendant + annotated tag) and shim checks against one temporary clone; any failure is a reason, never an exception."""
    if not _SHA_RE.match(new_sha) or (old_sha is not None and not _SHA_RE.match(old_sha)):
        return (f"invalid agent-ratchet SHA ({old_sha!r} -> {new_sha!r})",)
    try:
        with tempfile.TemporaryDirectory(prefix="agent_ratchet_clone_") as tmp:
            git_dir, clone_err = _clone(repo_url, tmp)
            if git_dir is None:
                return (clone_err or f"cannot clone agent-ratchet from {repo_url}",)
            errs = [_release_error(git_dir, old_sha, new_sha, extras) if check_release else None, _shim_error(git_dir, new_sha, shim) if check_shim else None]
            return tuple(e for e in errs if e is not None)
    except (OSError, subprocess.SubprocessError) as exc:
        return (f"cannot verify agent-ratchet {new_sha} against {repo_url}: {exc}",)


def released_descendant_error(old_sha: str | None, new_sha: str, repo_url: str = GUARD_CORE_URL) -> str | None:
    errs = _remote_errors(repo_url, old_sha, new_sha, True, None, False)
    return errs[0] if errs else None


def _legacy_manifest_errors(base_manifest: bytes | None, target_manifest: bytes | None) -> list[str]:
    if base_manifest is None:
        return []
    if target_manifest is None:
        return [LEGACY_DELETED_MSG]
    return [LEGACY_CHANGED_MSG] if target_manifest != base_manifest else []


def adopted_guard_files(base_prefix: str, target_prefix: str, deleted: Iterable[str], cwd: str | None = None) -> frozenset[str]:
    """Deleted 2.x guard files that the diff retires by adopting ``guard.lock``.

    Only when base has the legacy manifest and no lock, target has a valid regular lock and no manifest, and the
    deleted blob in base is byte-identical to its manifest sha256. Any malformed input yields no exemption.
    """
    try:
        if entry_mode(base_prefix, LOCK_PATH, cwd) is not None or entry_mode(target_prefix, LOCK_PATH, cwd) != "100644":
            return frozenset()
        if read_lock_spec(target_prefix, cwd=cwd) is None or _read_ref_file_bytes(target_prefix, LEGACY_MANIFEST_PATH, cwd=cwd) is not None:
            return frozenset()
        manifest = json.loads(_read_ref_file_bytes(base_prefix, LEGACY_MANIFEST_PATH, cwd=cwd) or b"null")
        files = manifest.get("files") if isinstance(manifest, dict) else None
        if not isinstance(files, dict):
            return frozenset()
        listed = {p: _read_ref_file_bytes(base_prefix, p, cwd=cwd) for p in deleted if p in files}
        return frozenset(
            p for p, blob in listed.items() if blob is not None and isinstance(files[p], str) and files[p].lower() == hashlib.sha256(blob).hexdigest()
        )
    except (GuardAnalysisError, ValueError, RecursionError):
        return frozenset()


def verify_lock_transition(
    base_prefix: str | None, target_prefix: str, cwd: str | None = None, *, local: bool, repo_url: str = GUARD_CORE_URL
) -> list[str]:
    target_modes = {p: entry_mode(target_prefix, p, cwd) for p in _ALLOWED_MODES}
    for rel_path, mode in target_modes.items():
        if mode is not None and mode not in _ALLOWED_MODES[rel_path]:
            return [_mode_msg(rel_path, mode)]
    base_modes = {p: entry_mode(base_prefix, p, cwd) for p in _ALLOWED_MODES}
    base_lock_mode = base_modes[LOCK_PATH]
    if base_lock_mode is not None and base_lock_mode not in _ALLOWED_MODES[LOCK_PATH]:
        return [f"{LOCK_PATH} in the base is not a regular file (mode {base_lock_mode}); a lock transition cannot be verified"]
    base_valid = {p: m in _ALLOWED_MODES[p] for p, m in base_modes.items()}
    base_lock = read_lock_spec(base_prefix, cwd=cwd) if base_prefix is not None and base_valid[LOCK_PATH] else None
    target_lock = read_lock_spec(target_prefix, cwd=cwd)
    base_shim = _snapshot_bytes(base_prefix, SHIM_PATH, cwd) if base_valid[SHIM_PATH] else None
    target_shim = _snapshot_bytes(target_prefix, SHIM_PATH, cwd)
    target_manifest = _snapshot_bytes(target_prefix, LEGACY_MANIFEST_PATH, cwd)
    lock_changed = base_lock != target_lock or base_modes[LOCK_PATH] != target_modes[LOCK_PATH]
    shim_changed = base_shim != target_shim or base_modes[SHIM_PATH] != target_modes[SHIM_PATH]
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
    return list(
        _remote_errors(repo_url, base_lock.sha if base_lock else None, target_lock.sha, lock_changed, target_shim, lock_changed or shim_changed, target_lock.extras)
    )


def _trusted_fork_point(cwd: str | None) -> str | None:
    """merge-base(trusted, HEAD) for the first resolvable CI/default-branch candidate (as ``resolve_base_ref``, minus HEAD)."""
    for ref in trusted_base_candidates(cwd):
        sha = _git_out(["rev-parse", "--verify", "-q", f"{ref}^{{commit}}"], cwd)
        if sha:
            return (_git_out(["merge-base", sha, "HEAD"], cwd) or sha) if head_commit_exists(cwd) else sha
    return None


def _pin_present(cwd: str | None) -> bool:
    return any(entry_mode(ref, p, cwd) is not None for ref in ("", "HEAD") for p in _ALLOWED_MODES)


def staged_lock_errors(cwd: str | None = None, *, require_base_ref: bool = False, repo_url: str = GUARD_CORE_URL) -> list[str]:
    """Pre-commit check of the index: fork point with the trusted base -> index by the remote alone, then HEAD -> index with the env gate."""
    base = _trusted_fork_point(cwd)
    if base is None and require_base_ref and _pin_present(cwd):
        raise GuardAnalysisError(f"--require-base-ref: no trusted base ref to judge {LOCK_PATH}/{SHIM_PATH} against")
    errs = verify_lock_transition(base, "", cwd=cwd, local=False, repo_url=repo_url) if base else []
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
