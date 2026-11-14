#!/usr/bin/env python3
"""Shared Git, index-isolation, file budget (cognitive / LOC transition), and manifest/config I/O for Guard Core 2.3.3."""

from __future__ import annotations

import ast
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from typing import Any, Mapping, NamedTuple, Sequence

from guard_core.cognitive_complexity import COGNITIVE_MODULE_CEILING, evaluate_cognitive_budget
from guard_core.source_metrics import (  # noqa: F401 -- lexing primitives re-exported
    JS_LIKE_EXTS as JS_LIKE_EXTS, _count_ast_assertions, _count_js_assertions, count_effective_sloc as count_effective_sloc,
)
from guard_core.guard_versions import (  # noqa: F401 -- version constants re-exported
    AUTHORIZED_GUARD_VERSION_UPGRADES, GUARD_VERSION, KNOWN_GUARD_VERSION_ORDER, RUNTIME_SCANNER_SINCE, default_remote_refs, required_runtime_files,
)

MODIFIED_FILE_SOFT_CEILING_LOC: int = 680
HARD_FILE_CEILING_LOC: int = 800
HARD_RAW_LOC_SAFETY_CEILING: int = 950
MAX_FUNCTION_ARGS: int = 5
MAX_CONTROL_NESTING_DEPTH: int = 4
APP_CODE_PREFIXES: tuple[str, ...] = ("src/", "backend/", "web/", "mobile/", "packages/")
DEFAULT_IMPORT_ROOTS: tuple[str, ...] = (".", "src", "backend", "web", "mobile", "packages")
CODE_SCAN_EXTS: tuple[str, ...] = (".py",) + JS_LIKE_EXTS
DUMPING_GROUND_FILENAME_RE: re.Pattern[str] = re.compile(
    r"(?:^|/)(?:_?(?:helpers|utils|common|misc|shared|ext|extra)|.*_(?:helpers|utils|common|misc|ext))\.(?:py|ts|tsx|mts|cts|js|jsx|mjs|cjs)$"
)

SELF_SKIP_NAMES: set[str] = {
    "ai_slop_scanner.py", "refactoring_guard.py", "ast_refactoring_delta.py", "ast_topology_guard.py",
    "git_guard_io.py", "source_metrics.py", "query_mutation_rules.py", "ast_control_flow.py", "baseline_diff.py", "cognitive_complexity.py", "guard_versions.py", "test_baseline_integrity.py", "test_ai_slop_scanner.py", "test_agent_slop_scanner.py",
    "test_baseline_integrity_guard.py", "test_guard_conformance.py", "test_guard_git_conformance.py", "test_guard_cognitive_conformance.py",
    "test_guard_topology_conformance.py", "guard_repo_harness.py",
    "ai_slop_scanner.test.ts", "test_quality_auditor.py", "test_suite_quality_ratchet.py",
}


class SlopViolation(NamedTuple):
    file: str
    line: int
    category: str
    message: str
    snippet: str


def is_test_filename(filename: str) -> bool:
    name = os.path.basename(filename)
    parent_parts = Path(filename).parts[:-1]
    return (
        any(p in ("test", "tests", "__tests__") for p in parent_parts)
        or name.startswith("test_")
        or name.endswith(("_test.py", ".test.js", ".spec.js", ".test.jsx", ".spec.jsx", ".test.mjs", ".spec.mjs", ".test.ts", ".spec.ts", ".test.tsx", ".spec.tsx", ".test.mts", ".spec.mts"))
    )


RUNTIME_SCANNER_FILES: tuple[str, ...] = tuple(RUNTIME_SCANNER_SINCE)
SYNCHRONIZED_GUARD_FILES: tuple[str, ...] = RUNTIME_SCANNER_FILES + (
    "tests/ci/test_guard_conformance.py", "tests/ci/test_guard_git_conformance.py", "tests/ci/test_guard_cognitive_conformance.py",
    "tests/ci/test_guard_topology_conformance.py", "tests/ci/guard_repo_harness.py",
)
PROTECTED_GOVERNANCE_FILES: set[str] = set(SYNCHRONIZED_GUARD_FILES) | {
    "scripts/audit/guard_manifest.json", "scripts/audit/audit_guard_config.json",
    "tests/test_architecture_boundaries.py", ".githooks/pre-commit", ".husky/pre-commit", ".gitlab-ci.yml",
}
PROTECTED_GOVERNANCE_PREFIXES: tuple[str, ...] = (
    "scripts/audit/", "scripts/hooks/", "scripts/ci/",
    "tests/baselines/", "tests/meta_guards/",
    ".githooks/", ".husky/", ".github/workflows/",
)


def is_protected_governance_path(rel_path: str) -> bool:
    return rel_path in PROTECTED_GOVERNANCE_FILES or rel_path.startswith(PROTECTED_GOVERNANCE_PREFIXES)


NEW_2_1_SLOP_KINDS: frozenset[str] = frozenset({"domain_impurity", "excessive_nesting_depth", "query_mutation_side_effect"})
LEGACY_2_0_SLOP_KINDS: frozenset[str] = frozenset({
    "defensive_getattr_slop", "empty_subclass_alias", "excessive_parameter_list", "global_monkeypatch_state",
    "monkeypatch_binding", "nested_or_late_import", "passthrough_wrapper_bloat", "reexport_facade_aliasing",
    "swallowed_fallback_return", "symbol_alias_bloat",
})


class GuardAnalysisError(RuntimeError):
    """Raised when AST parsing, Git resolution, or config/manifest validation fails."""


def head_commit_exists(cwd: str | None = None) -> bool:
    return subprocess.run(["git", "rev-parse", "--verify", "HEAD^{commit}"], cwd=cwd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def verify_commit_ref(ref: str, cwd: str | None = None) -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "--verify", f"{ref}^{{commit}}"], cwd=cwd, text=True, stderr=subprocess.PIPE).strip()
    except subprocess.CalledProcessError as exc:
        raise GuardAnalysisError(f"Cannot resolve commit ref '{ref}': {exc.stderr.strip() if exc.stderr else exc}") from exc


def git_cat_bytes(spec: str, cwd: str | None = None) -> bytes | None:
    if spec.startswith("HEAD:") and not head_commit_exists(cwd):
        return None
    res = subprocess.run(["git", "cat-file", "blob", spec], cwd=cwd, capture_output=True, env={**os.environ, "LC_ALL": "C"})  # stable stderr
    if res.returncode == 0:
        return res.stdout
    err = (res.stderr or b"").decode("utf-8", errors="replace").lower()
    if "not a valid object name" in err or "does not exist" in err or "exists on disk, but not in" in err:
        return None
    raise GuardAnalysisError(f"git cat-file failed for '{spec}': {err.strip()}")


def git_show_text(spec: str, cwd: str | None = None) -> str | None:
    raw = git_cat_bytes(spec, cwd=cwd)
    if raw is None:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise GuardAnalysisError(f"Non-UTF8 source in '{spec}': {exc}") from exc


def parse_name_status_z(raw_bytes: bytes) -> list[tuple[str, str, str]]:
    if not raw_bytes:
        return []
    tokens = raw_bytes.decode("utf-8", errors="surrogateescape").split("\0")
    out: list[tuple[str, str, str]] = []
    idx = 0
    while idx < len(tokens) and tokens[idx]:
        status = tokens[idx]
        idx += 1
        if status.startswith(("R", "C")):
            if idx + 1 >= len(tokens):
                break
            old_p, new_p = tokens[idx], tokens[idx + 1]
            idx += 2
            out.append((status, old_p, new_p))
        else:
            if idx >= len(tokens):
                break
            p = tokens[idx]
            idx += 1
            out.append((status, p, p))
    return out


def diff_name_status(base_ref: str | None, target_ref: str | None = None, cwd: str | None = None) -> list[tuple[str, str, str]]:
    if target_ref is None:
        cmd = ["git", "diff", "--cached", "--name-status", "-M", "-z"]
        if not (base_ref in (None, "HEAD") and not head_commit_exists(cwd)):
            cmd.append(base_ref or "HEAD")
    else:
        assert base_ref is not None
        cmd = ["git", "diff", "--name-status", "-M", "-z", base_ref, target_ref]
    res = subprocess.run(cmd, cwd=cwd, capture_output=True)
    if res.returncode != 0:
        err = (res.stderr or b"").decode("utf-8", errors="replace").strip()
        raise GuardAnalysisError(f"git diff failed ({' '.join(cmd)}): {err}")
    return parse_name_status_z(res.stdout)


def list_snapshot_files(ref_prefix: str, cwd: str | None = None) -> list[str]:
    if ref_prefix == "WORKTREE":
        root = Path(cwd) if cwd else Path(".")
        out: list[str] = []
        for p in sorted(root.rglob("*")):
            if p.is_file() and ".git" not in p.parts:
                out.append(p.relative_to(root).as_posix())
        return out
    if ref_prefix == "":
        res = subprocess.run(["git", "ls-files", "-z"], cwd=cwd, capture_output=True)
        if res.returncode != 0:
            raise GuardAnalysisError("git ls-files failed")
        return [t for t in res.stdout.decode("utf-8", errors="replace").split("\0") if t]
    if ref_prefix == "HEAD" and not head_commit_exists(cwd):
        return []
    res = subprocess.run(["git", "ls-tree", "-r", "--name-only", "-z", ref_prefix], cwd=cwd, capture_output=True)
    if res.returncode != 0:
        err = (res.stderr or b"").decode("utf-8", errors="replace").strip()
        raise GuardAnalysisError(f"git ls-tree failed for '{ref_prefix}': {err}")
    return [t for t in res.stdout.decode("utf-8", errors="replace").split("\0") if t]


def parse_guard_config_bytes(raw: bytes, source: str) -> dict[str, Any]:
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GuardAnalysisError(f"Malformed audit_guard_config.json at {source}: {exc}") from exc
    if not isinstance(data, dict):
        raise GuardAnalysisError(f"audit_guard_config.json at {source} must be a JSON object")
    extra = data.get("extra_slop_rules", [])
    waivers = data.get("legacy_loc_waivers", [])
    roots = data.get("import_roots", list(DEFAULT_IMPORT_ROOTS))
    if not isinstance(extra, list) or not isinstance(waivers, list) or not isinstance(roots, list) or not roots:
        raise GuardAnalysisError(f"Invalid list fields in audit_guard_config.json at {source}")
    for rule in extra:
        if not isinstance(rule, dict) or not isinstance(rule.get("pattern"), str):
            raise GuardAnalysisError(f"Invalid rule in extra_slop_rules at {source}")
        try:
            re.compile(rule["pattern"])
        except re.error as exc:
            raise GuardAnalysisError(f"Invalid regex in extra_slop_rules at {source}: {exc}") from exc
    for w in waivers:
        if not isinstance(w, dict):
            raise GuardAnalysisError(f"Invalid waiver in legacy_loc_waivers at {source}")
    for r in roots:
        if not isinstance(r, str) or not r.strip():
            raise GuardAnalysisError(f"Invalid entry in import_roots at {source}")
    return {"extra_slop_rules": extra, "legacy_loc_waivers": waivers, "import_roots": roots}


def load_guard_config_for_ref(ref_prefix: str, cwd: str | None = None) -> dict[str, Any]:
    rel = "scripts/audit/audit_guard_config.json"
    default_cfg = {"extra_slop_rules": [], "legacy_loc_waivers": [], "import_roots": list(DEFAULT_IMPORT_ROOTS)}
    if ref_prefix == "WORKTREE":
        base_dir = Path(cwd) if cwd else Path(".")
        cfg_path = base_dir / rel
        if not cfg_path.exists():
            return default_cfg
        try:
            return parse_guard_config_bytes(cfg_path.read_bytes(), str(cfg_path))
        except OSError as exc:
            raise GuardAnalysisError(f"Cannot read {cfg_path}: {exc}") from exc
    spec = f"{ref_prefix}:{rel}" if ref_prefix else f":{rel}"
    raw = git_cat_bytes(spec, cwd=cwd)
    if raw is None:
        return default_cfg
    return parse_guard_config_bytes(raw, spec)


def resolve_trusted_base_ref(cwd: str | None = None) -> str | None:
    for ref in (*default_remote_refs(cwd), "HEAD"):
        if subprocess.run(["git", "rev-parse", "--verify", f"{ref}^{{commit}}"], cwd=cwd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
            return ref
    return None


def _read_ref_file_bytes(ref_prefix: str, rel_path: str, cwd: str | None = None) -> bytes | None:
    if ref_prefix == "WORKTREE":
        p = (Path(cwd) if cwd else Path(".")) / rel_path
        return p.read_bytes() if p.exists() else None
    spec = f"{ref_prefix}:{rel_path}" if ref_prefix else f":{rel_path}"
    return git_cat_bytes(spec, cwd=cwd)


def load_manifest_for_ref(ref_prefix: str, cwd: str | None = None) -> dict[str, Any] | None:
    rel = "scripts/audit/guard_manifest.json"
    raw = _read_ref_file_bytes(ref_prefix, rel, cwd=cwd)
    if raw is None:
        return None
    label = rel if ref_prefix == "WORKTREE" else (f"{ref_prefix}:{rel}" if ref_prefix else f":{rel}")
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GuardAnalysisError(f"Malformed {label}: {exc}") from exc
    if not isinstance(data, dict):
        raise GuardAnalysisError(f"{label} must be a JSON object")
    return data


def _is_authorized_manifest_version_step(b_ver: str, t_ver: str, allow_multi_hop: bool) -> bool:
    if not allow_multi_hop:
        return (b_ver, t_ver) in AUTHORIZED_GUARD_VERSION_UPGRADES
    return b_ver in KNOWN_GUARD_VERSION_ORDER and t_ver in KNOWN_GUARD_VERSION_ORDER and KNOWN_GUARD_VERSION_ORDER.index(b_ver) < KNOWN_GUARD_VERSION_ORDER.index(t_ver)


def _validate_manifest_structure(target_manifest: dict[str, Any], base_keys: set[str], target_prefix: str, cwd: str | None, require_current_version: bool) -> list[str]:
    files_map, t_ver = target_manifest.get("files"), target_manifest.get("guard_version")
    if not isinstance(files_map, dict) or not isinstance(t_ver, str) or (require_current_version and t_ver != GUARD_VERSION):
        return [f"Invalid or version-mismatched guard_manifest.json (guard_version={t_ver!r})"]
    missing = sorted((required_runtime_files(t_ver) | base_keys) - set(files_map))
    if missing:
        return [f"guard_manifest.json missing required file entries: {missing}"]
    for rel, expected_sha in files_map.items():
        blob = _read_ref_file_bytes(target_prefix, rel, cwd=cwd)
        if not isinstance(expected_sha, str) or blob is None or hashlib.sha256(blob).hexdigest() != expected_sha:
            return [f"{rel} SHA-256 does not match guard_manifest.json"]
    return []


def verify_guard_manifest_transition(
    base_prefix: str | None, target_prefix: str, cwd: str | None = None, require_current_version: bool = False, allow_multi_hop: bool = False
) -> list[str]:
    base_manifest = load_manifest_for_ref(base_prefix, cwd=cwd) if base_prefix and (base_prefix != "HEAD" or head_commit_exists(cwd)) else None
    target_manifest = load_manifest_for_ref(target_prefix, cwd=cwd)
    if target_manifest is None:
        return ["scripts/audit/guard_manifest.json was deleted"] if base_manifest is not None else []
    base_keys = set(base_manifest["files"]) if base_manifest and isinstance(base_manifest.get("files"), dict) else set()
    errs = _validate_manifest_structure(target_manifest, base_keys, target_prefix, cwd, require_current_version)
    if errs or base_manifest is None or target_manifest == base_manifest or os.environ.get("ALLOW_GUARD_MANIFEST_UPDATE") == "1":
        return errs
    b_ver, t_ver = str(base_manifest.get("guard_version") or ""), str(target_manifest.get("guard_version") or "")
    if not _is_authorized_manifest_version_step(b_ver, t_ver, allow_multi_hop):
        return [f"Unauthorized guard_manifest.json change ({b_ver} -> {t_ver}) without ALLOW_GUARD_MANIFEST_UPDATE=1"]
    return []


def _verify_staged_manifest(cwd: str | None = None) -> int | None:
    try:
        trusted_ref = resolve_trusted_base_ref(cwd)
        errs = verify_guard_manifest_transition(trusted_ref, "", cwd=cwd, require_current_version=True)
        if not errs and head_commit_exists(cwd) and trusted_ref != "HEAD":
            errs = verify_guard_manifest_transition("HEAD", "", cwd=cwd, require_current_version=True)
    except GuardAnalysisError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    if errs:
        print(f"ERROR: {errs[0]}", file=sys.stderr)
        return 2
    return None


def maybe_reexec_from_index(
    entrypoint_script: str,
    require_flag: str | None = None,
) -> int | None:
    if os.environ.get("_AUDIT_GUARD_MATERIALIZED") == "1" and "audit_guard_idx_" in Path(entrypoint_script).as_posix():
        return None
    if require_flag is not None:
        if require_flag not in sys.argv:
            return None
    elif "--commit-range" in sys.argv or "--base-ref" in sys.argv:
        return None
    manifest_err = _verify_staged_manifest()
    if manifest_err is not None:
        sys.exit(manifest_err)

    tracked_check_paths = RUNTIME_SCANNER_FILES + (
        "scripts/audit/guard_manifest.json",
        "scripts/audit/audit_guard_config.json",
    )
    drifted = False
    staged_blobs: dict[str, bytes] = {}
    for rel in tracked_check_paths:
        blob = git_cat_bytes(f":{rel}")
        disk_path = Path(rel)
        if blob is None:
            if rel in RUNTIME_SCANNER_FILES:
                return None
            if disk_path.exists():
                drifted = True
            continue
        staged_blobs[rel] = blob
        if not disk_path.exists() or disk_path.read_bytes() != blob:
            drifted = True

    if not drifted:
        return None

    with tempfile.TemporaryDirectory(prefix="audit_guard_idx_") as tmp:
        tmp_root = Path(tmp)
        (tmp_root / "scripts").mkdir(parents=True, exist_ok=True)
        (tmp_root / "scripts" / "__init__.py").write_text("", encoding="utf-8")
        tmp_audit = tmp_root / "scripts" / "audit"
        tmp_audit.mkdir(parents=True, exist_ok=True)
        (tmp_audit / "__init__.py").write_text("", encoding="utf-8")
        for rel, blob in staged_blobs.items():
            dst = tmp_root / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(blob)
        env = dict(os.environ)
        env["_AUDIT_GUARD_MATERIALIZED"] = "1"
        existing_pp = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = f"{tmp_root}{os.pathsep}{existing_pp}" if existing_pp else str(tmp_root)
        target_script = tmp_audit / Path(entrypoint_script).name
        res = subprocess.run([sys.executable, str(target_script), *sys.argv[1:]], env=env)
        sys.exit(res.returncode)


def extract_changed_lines_map(diff_text: str) -> dict[str, set[int]]:
    changed: dict[str, set[int]] = {}
    current_file, lineno = "", 0
    for raw_line in diff_text.splitlines():
        if raw_line.startswith("+++ b/"):
            current_file, lineno = raw_line[6:].strip(), 0
        elif raw_line.startswith("@@ "):
            m = re.search(r"\+(\d+)", raw_line)
            lineno = int(m.group(1)) - 1 if m else 0
        elif raw_line.startswith("+") and not raw_line.startswith("+++"):
            lineno += 1
            if current_file:
                changed.setdefault(current_file, set()).add(lineno)
        elif not raw_line.startswith("-"):
            lineno += 1
    return changed


def _check_single_loc_waiver_diff(w_file: str, b_w: Mapping[str, Any], t_w: Mapping[str, Any]) -> str | None:
    if dict(t_w) == dict(b_w):
        return None
    for num_key in ("max_loc", "max_delta"):
        b_val, t_val = b_w.get(num_key), t_w.get(num_key)
        if isinstance(b_val, int) and not isinstance(b_val, bool):
            if not (isinstance(t_val, int) and not isinstance(t_val, bool)) or t_val > b_val:
                return f"legacy_loc_waivers {num_key} increased or invalidated for '{w_file}': {b_val} -> {t_val}"
        elif num_key in t_w:
            return f"legacy_loc_waivers {num_key} added for '{w_file}'"
    if t_w.get("base_blob_sha256") != b_w.get("base_blob_sha256"):
        return f"legacy_loc_waivers base_blob_sha256 mutation is forbidden for '{w_file}'"
    return None


def _check_extra_slop_rules_monotonicity(base_rules: Sequence[Mapping[str, Any]], target_rules: Sequence[Mapping[str, Any]]) -> list[str]:
    t_map = {(str(r.get("category", "")), str(r.get("pattern", ""))): bool(r.get("test_only", False)) for r in target_rules if isinstance(r, Mapping)}
    errs: list[str] = []
    for r in base_rules:
        if not isinstance(r, Mapping):
            continue
        key = (str(r.get("category", "")), str(r.get("pattern", "")))
        if key not in t_map:
            errs.append(f"extra_slop_rules entry deleted: {key[0]}:{key[1]}")
        elif not bool(r.get("test_only", False)) and t_map[key]:
            errs.append(f"extra_slop_rules entry weakened to test_only: {key[0]}:{key[1]}")
    return errs


def verify_audit_guard_config_monotonicity(base_prefix: str, target_prefix: str, cwd: str | None = None) -> list[str]:
    if not base_prefix or (base_prefix == "HEAD" and not head_commit_exists(cwd)):
        return []
    rel = "scripts/audit/audit_guard_config.json"
    b_raw, t_raw = _read_ref_file_bytes(base_prefix, rel, cwd=cwd), _read_ref_file_bytes(target_prefix, rel, cwd=cwd)
    if b_raw is not None and t_raw is None:
        return ["scripts/audit/audit_guard_config.json was deleted"]
    if b_raw == t_raw:
        return []
    b_cfg, t_cfg = load_guard_config_for_ref(base_prefix, cwd=cwd), load_guard_config_for_ref(target_prefix, cwd=cwd)
    errors = _check_extra_slop_rules_monotonicity(b_cfg.get("extra_slop_rules", []), t_cfg.get("extra_slop_rules", []))
    base_waivers, target_waivers = b_cfg.get("legacy_loc_waivers", []), t_cfg.get("legacy_loc_waivers", [])
    if base_waivers == target_waivers:
        return errors
    base_map = {str(w.get("file") or w.get("path") or "").strip(): w for w in base_waivers if isinstance(w, Mapping)}
    seen: set[str] = set()
    for t_w in target_waivers:
        w_file = str(t_w.get("file") or t_w.get("path") or "").strip() if isinstance(t_w, Mapping) else ""
        if not w_file or w_file in seen or w_file not in base_map:
            errors.append(f"New or duplicate legacy_loc_waivers entry forbidden: '{w_file or t_w}'")
            continue
        seen.add(w_file)
        err = _check_single_loc_waiver_diff(w_file, base_map[w_file], t_w)
        if err:
            errors.append(err)
    return errors


def _waiver_permits_loc(rel_path: str, base_bytes: bytes, b_loc: int, t_loc: int, waivers: Sequence[Mapping[str, Any]]) -> bool:
    base_sha = hashlib.sha256(base_bytes).hexdigest()
    for w in waivers:
        max_loc, max_delta = w.get("max_loc"), w.get("max_delta")
        if (
            (w.get("file") or w.get("path")) == rel_path
            and w.get("base_blob_sha256") == base_sha
            and isinstance(max_loc, int) and not isinstance(max_loc, bool)
            and isinstance(max_delta, int) and not isinstance(max_delta, bool)
            and max_loc <= HARD_FILE_CEILING_LOC
            and t_loc <= max_loc
            and (t_loc - b_loc) <= max_delta
        ):
            return True
    return False


def evaluate_loc_transition(
    rel_path: str, status: str, base_bytes: bytes | None, target_bytes: bytes,
    soft_ceiling: int = MODIFIED_FILE_SOFT_CEILING_LOC, waivers: Sequence[Mapping[str, Any]] = (), ceiling_override: int | None = None,
) -> tuple[list[SlopViolation], int]:
    budget_ceiling = COGNITIVE_MODULE_CEILING if rel_path.endswith(".py") else soft_ceiling
    if status.startswith("A") and DUMPING_GROUND_FILENAME_RE.search(rel_path):
        msg = f"Creating dumping-ground module '{rel_path}' (*_helpers/*_utils) is forbidden (Zero-S6). Use cohesive domain modules."
        return [SlopViolation(rel_path, 1, "modified_file_loc_buffer", msg, rel_path)], budget_ceiling
    if not rel_path.startswith(APP_CODE_PREFIXES) or not rel_path.endswith(CODE_SCAN_EXTS):
        return [], budget_ceiling

    target_text = target_bytes.decode("utf-8", errors="replace")
    base_text = base_bytes.decode("utf-8", errors="replace") if base_bytes is not None else ""
    t_raw, b_raw = len(target_text.splitlines()), (len(base_text.splitlines()) if base_bytes is not None else 0)
    if t_raw > HARD_RAW_LOC_SAFETY_CEILING and t_raw > b_raw:
        msg = f"File '{rel_path}' raw line count ({t_raw}) exceeds hard safety ceiling {HARD_RAW_LOC_SAFETY_CEILING} LOC."
        return [SlopViolation(rel_path, t_raw, "modified_file_loc_buffer", msg, f"{b_raw} -> {t_raw} raw LOC")], ceiling_override if ceiling_override is not None else budget_ceiling
    t_loc, b_loc = count_effective_sloc(rel_path, target_text), (count_effective_sloc(rel_path, base_text) if base_bytes is not None else 0)
    if rel_path.endswith(".py"):  # Python: cognitive complexity ratchet plus the hard effective-SLOC backstop.
        findings, ceiling = evaluate_cognitive_budget(rel_path, base_text if base_bytes is not None else None, target_text, ceiling_override)
        out = [SlopViolation(rel_path, f.line, "cognitive_complexity_budget", f.message, f.detail) for f in findings]
        if t_loc > HARD_FILE_CEILING_LOC and t_loc > b_loc:
            out.insert(0, SlopViolation(rel_path, t_loc, "modified_file_loc_buffer", f"File '{rel_path}' grew to {t_loc} effective SLOC, exceeding the hard backstop {HARD_FILE_CEILING_LOC} SLOC.", f"{b_loc} -> {t_loc} LOC"))
        return out, ceiling
    allowed_loc = ceiling_override if ceiling_override is not None else max(soft_ceiling, b_loc)
    if t_loc <= allowed_loc:
        return [], max(soft_ceiling, t_loc)
    if base_bytes is not None and t_loc <= HARD_FILE_CEILING_LOC and _waiver_permits_loc(rel_path, base_bytes, b_loc, t_loc, waivers):
        return [], t_loc
    msg = (
        f"Modified file '{rel_path}' grew to {t_loc} LOC, exceeding allowed ceiling {allowed_loc} LOC (Zero-S6)."
        if b_loc <= soft_ceiling
        else f"Legacy file '{rel_path}' ({b_loc} LOC > {soft_ceiling}) grew to {t_loc} LOC without an active legacy_loc_waiver."
    )
    return [SlopViolation(rel_path, t_loc, "modified_file_loc_buffer", msg, f"{b_loc} -> {t_loc} LOC")], allowed_loc


def check_staged_file_size_buffer(cwd: str | None = None, soft_ceiling: int = MODIFIED_FILE_SOFT_CEILING_LOC, waivers: Sequence[Mapping[str, Any]] = ()) -> list[SlopViolation]:
    violations: list[SlopViolation] = []
    for status, old_path, new_path in diff_name_status(None, None, cwd=cwd):
        if status.startswith("D") or is_test_filename(new_path) or os.path.basename(new_path) in SELF_SKIP_NAMES:
            continue
        target_bytes = git_cat_bytes(f":{new_path}", cwd)
        if target_bytes is not None:
            base_bytes = None if status.startswith("A") else git_cat_bytes(f"HEAD:{old_path}", cwd)
            step_v, _ = evaluate_loc_transition(new_path, status, base_bytes, target_bytes, soft_ceiling=soft_ceiling, waivers=waivers)
            violations.extend(step_v)
    return violations


def count_test_assertions(content: str, filename: str, strict: bool = False) -> int:
    if filename.endswith(".py"):
        try:
            tree = ast.parse(content, filename=filename)
        except SyntaxError as exc:
            if strict:
                raise GuardAnalysisError(f"SyntaxError in test file {filename}:{exc.lineno or 1}: {exc.msg}") from exc
            return 0
        return _count_ast_assertions(tree, multiplier=1)
    if filename.endswith(JS_LIKE_EXTS):
        return _count_js_assertions(content)
    return 0


git_show_bytes = git_cat_bytes
