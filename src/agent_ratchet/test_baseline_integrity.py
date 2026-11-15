#!/usr/bin/env python3
"""Tamper-Proof Baseline Integrity, Per-Commit DAG Ratchet & Policy Isolation Engine (2.3.3 rules, guard.lock pin)."""

from __future__ import annotations

import argparse
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any

from agent_ratchet.git_guard_io import (
    APP_CODE_PREFIXES,
    PROTECTED_GOVERNANCE_FILES, PROTECTED_GOVERNANCE_PREFIXES,
    GuardAnalysisError, diff_name_status, git_cat_bytes, head_commit_exists, trusted_base_candidates,
    is_protected_governance_path as is_protected_governance_path,
    verify_audit_guard_config_monotonicity, verify_commit_ref,
)
from agent_ratchet.lock_policy import LOCK_PATH, check_staged_lock, lock_check_is_local, verify_lock_transition

from agent_ratchet.baseline_diff import (
    BaselineDiffResult as BaselineDiffResult, _has_strict_improvement, _is_ceiling_key as _is_ceiling_key,
    _join_ratchet_states, evaluate_baseline_diff as evaluate_baseline_diff,
)

BaselineAnalysisError = GuardAnalysisError
ISOLATED_CODE_PREFIXES: tuple[str, ...] = APP_CODE_PREFIXES + ("tests/", "scripts/")

__all__ = [
    "APP_CODE_PREFIXES", "BaselineAnalysisError", "BaselineDiffResult", "ISOLATED_CODE_PREFIXES",
    "PROTECTED_GOVERNANCE_FILES", "PROTECTED_GOVERNANCE_PREFIXES",
    "_is_ceiling_key", "check_baseline_file", "evaluate_baseline_diff", "get_base_content",
    "is_protected_governance_path", "resolve_base_ref",
]


def _canonicalize_baseline_paths(data: dict[str, Any], rename_map: dict[str, str]) -> dict[str, Any]:
    if not rename_map:
        return data
    cloned = copy.deepcopy(data)
    for key, val in cloned.items():
        if isinstance(val, list):
            for item in val:
                if isinstance(item, dict) and isinstance(item.get("file"), str):
                    item["file"] = rename_map.get(item["file"], item["file"])
            cloned[key] = [rename_map.get(item, item) if isinstance(item, str) else item for item in val]
    return cloned


def _diff_entries(base_ref: str, target_ref: str | None, cwd: str | None = None) -> list[tuple[str, str, str]]:
    if target_ref == "WORKTREE":
        res = subprocess.run(["git", "diff", "-M", "-z", "--name-status", base_ref], cwd=cwd, capture_output=True)
        if res.returncode != 0:
            raise BaselineAnalysisError("git diff WORKTREE failed")
        from agent_ratchet.git_guard_io import parse_name_status_z
        return parse_name_status_z(res.stdout)
    return diff_name_status(base_ref, target_ref, cwd=cwd)


def _rename_map_from_entries(entries: list[tuple[str, str, str]]) -> dict[str, str]:
    return {old_p: new_p for status, old_p, new_p in entries if status.startswith("R")}


def _load_json_blob(spec: str, cwd: str | None = None) -> tuple[bytes | None, dict[str, Any] | None]:
    raw = git_cat_bytes(spec, cwd=cwd)
    if raw is None:
        return None, None
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BaselineAnalysisError(f"Failed to parse JSON in '{spec}': {exc}") from exc
    if not isinstance(parsed, dict):
        raise BaselineAnalysisError(f"JSON root in '{spec}' must be an object.")
    return raw, parsed


def _is_pure_rename_baseline_update(entries: list[tuple[str, str, str]], gov_paths: list[str], base_ref: str, target_ref: str | None, cwd: str | None = None) -> bool:
    rename_map = _rename_map_from_entries(entries)
    if not rename_map or not all(p.startswith("tests/baselines/") and p.endswith(".json") for p in gov_paths):
        return False
    t_prefix = target_ref or ""
    for bf in gov_paths:
        _, b_data = _load_json_blob(f"{base_ref}:{bf}", cwd=cwd)
        _, c_data = _load_json_blob(f"{t_prefix}:{bf}" if t_prefix else f":{bf}", cwd=cwd)
        if b_data is None or c_data is None or _canonicalize_baseline_paths(b_data, rename_map) != c_data:
            return False
    return True


def _is_atomic_baseline_tightening(entries: list[tuple[str, str, str]], gov_paths: list[str], base_ref: str, target_ref: str | None, cwd: str | None) -> bool:
    if not all(p.endswith(".json") and (p.startswith("tests/baselines/") or p.startswith("scripts/audit/baselines/")) for p in gov_paths):
        return False
    rename_map, t_prefix = _rename_map_from_entries(entries), target_ref or ""
    for bf in gov_paths:
        _, b_data = _load_json_blob(f"{base_ref}:{bf}", cwd=cwd)
        _, c_data = _load_target_baseline(bf, t_prefix, cwd=cwd)
        if b_data is None or c_data is None:
            return False
        canon_base = _canonicalize_baseline_paths(b_data, rename_map)
        if set(c_data) != set(canon_base) or not evaluate_baseline_diff(canon_base, c_data).is_valid or not _has_strict_improvement(canon_base, c_data):
            return False
    return True


def _check_single_commit_policy_isolation(base_ref: str, target_ref: str | None, cwd: str | None = None) -> tuple[bool, str]:
    entries = _diff_entries(base_ref, target_ref, cwd=cwd)
    touched = [new_p for _, _, new_p in entries] + [old_p for status, old_p, _ in entries if status.startswith("D")]
    code_paths = sorted({p for p in touched if (p.startswith(ISOLATED_CODE_PREFIXES) or p.startswith("test/")) and not is_protected_governance_path(p)})
    gov_paths = sorted({p for p in touched if is_protected_governance_path(p)})
    if not code_paths or not gov_paths:
        return True, "OK"
    if _is_pure_rename_baseline_update(entries, gov_paths, base_ref, target_ref, cwd=cwd):
        return True, "OK (mechanical git mv baseline path update)"
    if _is_atomic_baseline_tightening(entries, gov_paths, base_ref, target_ref, cwd=cwd):
        return True, "OK (atomic baseline tightening)"
    label = target_ref or "INDEX"
    return False, f"Policy isolation violation in {label}: commit mixes PROTECTED_GOVERNANCE_PATHS {gov_paths} with code/test/script changes {code_paths}."


def _check_merge_commit_policy_isolation(commit_sha: str, parents: list[str], cwd: str | None = None) -> tuple[bool, str]:
    all_changed: set[str] = set()
    for p in parents:
        for _, old_p, new_p in _diff_entries(p, commit_sha, cwd=cwd):
            all_changed.update(x for x in (old_p, new_p) if x)
    novel_paths: set[str] = set()
    unconflicted_novel_paths: set[str] = set()
    for path in all_changed:
        c_blob = git_cat_bytes(f"{commit_sha}:{path}", cwd=cwd)
        p_blobs = [git_cat_bytes(f"{parent}:{path}", cwd=cwd) for parent in parents]
        if all(pb != c_blob for pb in p_blobs):
            novel_paths.add(path)
            if len(set(p_blobs)) == 1:
                unconflicted_novel_paths.add(path)
    src_novel = sorted(p for p in novel_paths if p.startswith(APP_CODE_PREFIXES))
    gov_novel = sorted(p for p in novel_paths if is_protected_governance_path(p))
    if src_novel and gov_novel:
        return False, f"Merge commit {commit_sha} introduces mixed novel governance {gov_novel} and src/ {src_novel} changes."
    unconflicted_gov = sorted(p for p in unconflicted_novel_paths if is_protected_governance_path(p))
    any_src_changed = sorted(p for p in all_changed if p.startswith(APP_CODE_PREFIXES))
    if unconflicted_gov and any_src_changed:
        return False, f"Merge commit {commit_sha} introduces unconflicted governance edits {unconflicted_gov} alongside src/ merge {any_src_changed}."
    return True, "OK"


def resolve_base_ref(explicit_ref: str | None = None, require: bool = False) -> str | None:
    if explicit_ref:
        return verify_commit_ref(explicit_ref)
    for ref in (*trusted_base_candidates(), "HEAD"):
        try:
            return verify_commit_ref(ref)
        except BaselineAnalysisError:
            continue
    if require:
        raise BaselineAnalysisError("Could not resolve any base git reference (--require-base-ref).")
    return None


def _list_git_baseline_files(ref_prefix: str, baseline_dir: str | None, cwd: str | None = None) -> list[str]:
    dirs = [baseline_dir] if baseline_dir else ["scripts/audit/baselines", "tests/baselines"]
    if ref_prefix == "WORKTREE":
        base_dir = Path(cwd) if cwd else Path(".")
        return sorted(os.path.join(d, f) for d in dirs if (base_dir / d).exists() for f in sorted(os.listdir(base_dir / d)) if f.endswith(".json"))
    if ref_prefix == "HEAD" and not head_commit_exists(cwd):
        return []
    try:
        cmd = ["git", "ls-tree", "-r", "--name-only", ref_prefix, "--", *dirs] if ref_prefix else ["git", "ls-files", "--cached", "--", *dirs]
        out = subprocess.check_output(cmd, cwd=cwd, text=True, stderr=subprocess.DEVNULL)
        return sorted(ln.strip() for ln in out.splitlines() if ln.strip().endswith(".json"))
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        raise BaselineAnalysisError(f"Failed to enumerate git baseline files for '{ref_prefix or 'INDEX'}': {exc}") from exc


def _load_target_baseline(bf: str, t_prefix: str, cwd: str | None) -> tuple[bytes | None, dict[str, Any] | None]:
    if t_prefix != "WORKTREE":
        return _load_json_blob(f"{t_prefix}:{bf}" if t_prefix else f":{bf}", cwd=cwd)
    full_p = (Path(cwd) if cwd else Path(".")) / bf
    if not full_p.exists():
        return None, None
    try:
        c_raw = full_p.read_bytes()
        parsed = json.loads(c_raw.decode("utf-8"))
        if not isinstance(parsed, dict):
            raise BaselineAnalysisError(f"JSON root in {bf} must be an object.")
        return c_raw, parsed
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BaselineAnalysisError(f"Failed to parse JSON in {bf}: {exc}") from exc


def _seed_commit_ratchet_state(commit_sha: str, baseline_dir: str | None, cwd: str | None = None) -> dict[str, dict[str, Any]]:
    return {bf: data for bf in _list_git_baseline_files(commit_sha, baseline_dir, cwd=cwd) if (data := _load_json_blob(f"{commit_sha}:{bf}", cwd=cwd)[1]) is not None}


def _set_ratchet(out_ratchet: dict[str, dict[str, Any]] | None, bf: str, state: dict[str, Any]) -> None:
    if out_ratchet is not None:
        out_ratchet[bf] = state


def _evaluate_single_baseline_transition(bf: str, base_ref: str | None, t_prefix: str, entries: list[tuple[str, str, str]], rename_map: dict[str, str], parent_ratchet_state: dict[str, Any] | None, out_ratchet: dict[str, dict[str, Any]] | None, cwd: str | None) -> tuple[bool, str]:
    c_raw, c_data = _load_target_baseline(bf, t_prefix, cwd=cwd)
    initial = not base_ref or (base_ref == "HEAD" and not head_commit_exists(cwd))
    b_raw, b_git_data = (None, None) if initial else _load_json_blob(f"{base_ref}:{bf}", cwd=cwd)
    b_data = parent_ratchet_state if parent_ratchet_state is not None else b_git_data
    if c_data is None:
        return False, (f"FAIL: Baseline check failed for {bf}: [baseline_deleted] Baseline file {bf} was deleted." if b_data is not None else f"Baseline file {bf} does not exist.")
    if initial or b_data is None:
        _set_ratchet(out_ratchet, bf, c_data)
        return True, (f"OK: {bf} parsed cleanly (initial repository state)." if initial else f"OK: New baseline added: {bf}")
    canon_base = _canonicalize_baseline_paths(b_data, rename_map)
    res = evaluate_baseline_diff(canon_base, c_data)
    if not res.is_valid:
        return False, f"FAIL: Baseline check failed for {bf}: {res.reason}"
    _set_ratchet(out_ratchet, bf, _join_ratchet_states([canon_base, c_data]))
    return True, f"OK: {bf} passed baseline integrity check."


def _check_transition_baselines(base_ref: str | None, target_ref: str | None, baseline_dir: str | None, parent_ratchet: dict[str, dict[str, Any]] | None = None, out_ratchet: dict[str, dict[str, Any]] | None = None, cwd: str | None = None) -> tuple[bool, list[str]]:
    t_prefix = target_ref or ""
    files = sorted(set(_list_git_baseline_files(t_prefix, baseline_dir, cwd=cwd)) | (set(_list_git_baseline_files(base_ref, baseline_dir, cwd=cwd)) if base_ref else set()) | (set(parent_ratchet) if parent_ratchet else set()))
    has_base = bool(base_ref and (base_ref != "HEAD" or head_commit_exists(cwd)))
    entries = _diff_entries(base_ref, target_ref, cwd=cwd) if has_base and base_ref else []
    rename_map = _rename_map_from_entries(entries)
    messages: list[str] = []
    if has_base and base_ref and baseline_dir is None:
        messages.extend(f"FAIL: scripts/audit/audit_guard_config.json: {e}" for e in verify_audit_guard_config_monotonicity(base_ref, t_prefix, cwd=cwd))
        messages.extend(f"FAIL: {LOCK_PATH}: {e}" for e in verify_lock_transition(base_ref, t_prefix, cwd=cwd, local=lock_check_is_local(target_ref)))
    all_ok = not messages
    for bf in files:
        ok, msg = _evaluate_single_baseline_transition(bf, base_ref, t_prefix, entries, rename_map, parent_ratchet.get(bf) if parent_ratchet else None, out_ratchet, cwd)
        all_ok = all_ok and ok
        messages.append(msg)
    return all_ok, messages


def get_base_content(file_path: str, base_ref: str) -> str | None:
    raw = git_cat_bytes(f"{base_ref}:{file_path}")
    return raw.decode("utf-8") if raw is not None else None


def check_baseline_file(file_path: str, base_ref: str | None) -> tuple[bool, str]:
    ok, msgs = _check_transition_baselines(base_ref, None, os.path.dirname(file_path))
    matching = [m for m in msgs if file_path in m]
    return ok, (matching[0] if matching else (msgs[0] if msgs else "OK"))


def _step_merge_ratchet(c_sha: str, parents: list[str], enforce_isolation: bool, baseline_dir: str | None, ratchet_by_commit: dict[str, dict[str, dict[str, Any]]]) -> tuple[bool, list[str]]:
    if enforce_isolation:
        m_ok, m_msg = _check_merge_commit_policy_isolation(c_sha, parents)
        if not m_ok:
            return False, [f"FAIL: {m_msg}"]
    joined_parent: dict[str, dict[str, Any]] = {}
    for bf in sorted({bf for p in parents for bf in ratchet_by_commit[p]}):
        p_states = [ratchet_by_commit[p][bf] for p in parents if bf in ratchet_by_commit[p]]
        if len(p_states) < len(parents):
            return False, [f"FAIL: Baseline file {bf} missing in merge parent."]
        joined_parent[bf] = _join_ratchet_states(p_states)
    extra_errs: list[str] = []
    if baseline_dir is None:
        for p in parents[1:]:
            extra_errs.extend(f"FAIL: scripts/audit/audit_guard_config.json: {e}" for e in verify_audit_guard_config_monotonicity(p, c_sha))
            extra_errs.extend(f"FAIL: {LOCK_PATH}: {e}" for e in verify_lock_transition(p, c_sha, local=lock_check_is_local(c_sha)))
    c_state: dict[str, dict[str, Any]] = {}
    m_ok, m_msgs = _check_transition_baselines(parents[0], c_sha, baseline_dir, parent_ratchet=joined_parent, out_ratchet=c_state)
    if m_ok and not extra_errs:
        ratchet_by_commit[c_sha] = c_state
        return True, m_msgs
    return False, extra_errs + m_msgs


def _walk_commit_history(base_sha: str, head_sha: str, enforce_isolation: bool, baseline_dir: str | None) -> tuple[bool, list[str], dict[str, dict[str, dict[str, Any]]]]:
    commits = subprocess.check_output(["git", "rev-list", "--topo-order", "--reverse", f"{base_sha}..{head_sha}"], text=True).splitlines()
    ratchet_by_commit: dict[str, dict[str, dict[str, Any]]] = {base_sha: _seed_commit_ratchet_state(base_sha, baseline_dir)}
    for c_sha in commits:
        parents = subprocess.check_output(["git", "rev-list", "--parents", "-n", "1", c_sha], text=True).strip().split()[1:]
        for p in parents:
            ratchet_by_commit.setdefault(p, _seed_commit_ratchet_state(p, baseline_dir))
        if len(parents) == 1:
            if enforce_isolation:
                iso_ok, iso_msg = _check_single_commit_policy_isolation(parents[0], c_sha)
                if not iso_ok:
                    return False, [f"FAIL: {iso_msg}"], ratchet_by_commit
            c_state: dict[str, dict[str, Any]] = {}
            p_ok, p_msgs = _check_transition_baselines(parents[0], c_sha, baseline_dir, parent_ratchet=ratchet_by_commit[parents[0]], out_ratchet=c_state)
            if not p_ok:
                return False, p_msgs, ratchet_by_commit
            ratchet_by_commit[c_sha] = c_state
        elif len(parents) > 1:
            m_ok, m_msgs = _step_merge_ratchet(c_sha, parents, enforce_isolation, baseline_dir, ratchet_by_commit)
            if not m_ok:
                return False, m_msgs, ratchet_by_commit
    return True, [], ratchet_by_commit


def _evaluate_commit_range(range_spec: str, enforce_isolation: bool, baseline_dir: str | None) -> tuple[bool, list[str]]:
    if ".." not in range_spec:
        raise BaselineAnalysisError(f"Invalid --commit-range '{range_spec}'; expected <base>..<head>.")
    raw_base, raw_head = range_spec.split("..", 1)
    base_sha, head_sha = verify_commit_ref(raw_base), verify_commit_ref(raw_head)
    hist_ok, hist_msgs, ratchet_by_commit = _walk_commit_history(base_sha, head_sha, enforce_isolation, baseline_dir)
    if not hist_ok:
        return False, hist_msgs
    return _check_transition_baselines(base_sha, head_sha, baseline_dir, parent_ratchet=ratchet_by_commit.get(head_sha, ratchet_by_commit.get(base_sha)))


def _resolve_merge_base_with_head(base_ref: str) -> tuple[str, str | None]:
    if not head_commit_exists():
        return base_ref, None
    head_sha = verify_commit_ref("HEAD")
    try:
        mb = subprocess.check_output(["git", "merge-base", base_ref, head_sha], text=True, stderr=subprocess.DEVNULL).strip()
        return (mb or base_ref), head_sha
    except (subprocess.CalledProcessError, FileNotFoundError):
        return base_ref, head_sha


def _evaluate_local_state(explicit_base_ref: str | None, require_base_ref: bool, enforce_isolation: bool, baseline_dir: str | None, staged_only: bool = False) -> tuple[bool, list[str]]:
    target_mode: str | None = None if (enforce_isolation or staged_only) else "WORKTREE"
    base_ref = resolve_base_ref(explicit_base_ref, require=require_base_ref)
    if not base_ref:
        return _check_transition_baselines(None, target_mode, baseline_dir)
    anc_base, head_sha = _resolve_merge_base_with_head(base_ref)
    if enforce_isolation and head_sha:
        iso_ok, iso_msg = _check_single_commit_policy_isolation(head_sha, None)
        if not iso_ok:
            return False, [f"FAIL: {iso_msg}"]
    head_ratchet: dict[str, dict[str, Any]] | None = None
    if head_sha and anc_base != head_sha:
        hist_ok, hist_msgs, ratchet_by_commit = _walk_commit_history(anc_base, head_sha, False, baseline_dir)
        if not hist_ok:
            return False, hist_msgs
        head_ratchet = ratchet_by_commit.get(head_sha)
    elif head_sha:
        head_ratchet = _seed_commit_ratchet_state(head_sha, baseline_dir)
    if head_sha:
        return _check_transition_baselines(head_sha, target_mode, baseline_dir, parent_ratchet=head_ratchet, out_ratchet={})
    return _check_transition_baselines(anc_base, target_mode, baseline_dir)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit baseline monotonic descent & policy isolation guard")
    parser.add_argument("--test-violation-mock", action="store_true", help="Simulate baseline violation for meta-testing")
    parser.add_argument("--baseline-dir", default=None, help="Directory containing baseline JSON files")
    parser.add_argument("--base-ref", default=None, help="Explicit base git ref")
    parser.add_argument("--require-base-ref", action="store_true", help="Exit 2 if base git ref cannot be resolved")
    parser.add_argument("--enforce-policy-isolation", action="store_true", help="Reject single commits mixing governance and src/")
    parser.add_argument("--staged-only", action="store_true", help="Evaluate staged Git index instead of worktree")
    parser.add_argument("--commit-range", default=None, help="Commit range <base>..<head> for per-commit + final check")
    args = parser.parse_args(argv)

    if args.test_violation_mock:
        res = evaluate_baseline_diff({"metric": "type_escapes", "ceiling": 100, "exemptions": []}, {"metric": "type_escapes", "ceiling": 150, "exemptions": []})
        if not res.is_valid:
            print(f"FAIL: Simulated baseline violation detected: {res.reason}", file=sys.stderr)
            return 1
        return 0
    lock_rc = None if (args.commit_range or args.base_ref) else check_staged_lock(require_base_ref=args.require_base_ref)
    if lock_rc is not None:
        return lock_rc
    try:
        if args.commit_range:
            ok, msgs = _evaluate_commit_range(args.commit_range, args.enforce_policy_isolation, args.baseline_dir)
        else:
            ok, msgs = _evaluate_local_state(args.base_ref, args.require_base_ref, args.enforce_policy_isolation, args.baseline_dir, staged_only=args.staged_only)
    except BaselineAnalysisError as exc:
        print(f"ERROR: [guard_analysis_error] {exc}", file=sys.stderr)
        return 2
    stream = sys.stderr if not ok else sys.stdout
    for m in msgs:
        print(m, file=stream)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
