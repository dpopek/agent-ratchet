#!/usr/bin/env python3
"""Shared Git, index-isolation, file budget (cognitive / LOC transition), and config I/O; rules identical to Guard Core 2.3.3."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from typing import Any, Mapping, NamedTuple, Sequence

from agent_ratchet.ast_safety import (  # noqa: F401 -- fail-closed AST helpers re-exported
    GuardAnalysisError as GuardAnalysisError, parse_python as parse_python, visit_bounded as visit_bounded,
)
from agent_ratchet import external_config
from agent_ratchet.cognitive_complexity import COGNITIVE_MODULE_CEILING, evaluate_cognitive_budget
from agent_ratchet.json_safety import loads_bounded
from agent_ratchet.magento.config import validate_magento_exceptions
from agent_ratchet.php.scope import DEFAULT_PHP_PATHS, validate_exceptions, validate_php_paths
from agent_ratchet.profile import require_profile_capabilities
from agent_ratchet.rel_path import clean_rel_segments
from agent_ratchet.git_batch import (  # noqa: F401 -- head_commit_exists / _git_cat_bytes_oneshot re-exported
    _git_cat_bytes_oneshot as _git_cat_bytes_oneshot, active_reader_for, batch_unsafe,
    head_commit_exists as head_commit_exists,
)
from agent_ratchet.source_metrics import (  # noqa: F401 -- lexing primitives re-exported
    JS_LIKE_EXTS as JS_LIKE_EXTS, _count_ast_assertions, _count_js_assertions, count_effective_sloc as count_effective_sloc,
)

# Rule-set version: rule identifiers, thresholds and detection algorithms of Guard Core 2.3.3, not byte-identical
# findings; exemption scope may change without a bump. The package version lives in agent_ratchet.version.
RULES_VERSION: str = "2.3.3"
DEFAULT_BRANCH_CANDIDATES: tuple[str, ...] = ("origin/main", "origin/master")
_UNREACHABLE_DISTANCE = 1 << 62

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

# Vendored guard modules: exempt only under the protected governance prefix scripts/audit/.
GUARD_MODULE_NAMES: frozenset[str] = frozenset({
    "ai_slop_scanner.py", "refactoring_guard.py", "ast_refactoring_delta.py", "ast_topology_guard.py",
    "git_guard_io.py", "source_metrics.py", "query_mutation_rules.py", "ast_control_flow.py",
    "baseline_diff.py", "cognitive_complexity.py", "guard_versions.py", "test_baseline_integrity.py",
    "test_quality_auditor.py",
})
_SELF_SKIP_SCOPES: tuple[tuple[str, frozenset[str]], ...] = (("scripts/audit/", GUARD_MODULE_NAMES),)
NO_FIXTURES: frozenset[str] = frozenset()
FIXTURE_PATH_PREFIX = "tests/"


def is_self_skipped(path: str, *, fixture_paths: frozenset[str]) -> bool:
    """True for a guard module under scripts/audit/, or a path listed exactly in the protected config's fixture_paths."""
    name = path.rsplit("/", 1)[-1]
    return path in fixture_paths or any(path.startswith(prefix) and name in names for prefix, names in _SELF_SKIP_SCOPES)


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


# Frozen 2.3.3 consumer copies; kept only so these paths stay classified as protected governance paths.
SYNCHRONIZED_GUARD_FILES: tuple[str, ...] = (
    "scripts/audit/git_guard_io.py", "scripts/audit/refactoring_guard.py", "scripts/audit/ast_refactoring_delta.py",
    "scripts/audit/ast_topology_guard.py", "scripts/audit/ai_slop_scanner.py", "scripts/audit/test_baseline_integrity.py",
    "scripts/audit/cognitive_complexity.py", "scripts/audit/guard_versions.py", "scripts/audit/source_metrics.py",
    "scripts/audit/query_mutation_rules.py", "scripts/audit/ast_control_flow.py", "scripts/audit/baseline_diff.py",
    "tests/ci/test_guard_conformance.py", "tests/ci/test_guard_git_conformance.py", "tests/ci/test_guard_cognitive_conformance.py",
    "tests/ci/test_guard_topology_conformance.py", "tests/ci/guard_repo_harness.py",
)
PROTECTED_GOVERNANCE_FILES: set[str] = set(SYNCHRONIZED_GUARD_FILES) | {
    "guard.lock", "scripts/guard",
    "scripts/audit/guard_manifest.json", "scripts/audit/audit_guard_config.json",
    "tests/test_architecture_boundaries.py", ".githooks/pre-commit", ".husky/pre-commit", ".gitlab-ci.yml",
}
PROTECTED_GOVERNANCE_PREFIXES: tuple[str, ...] = (
    "scripts/audit/", "scripts/hooks/", "scripts/ci/",
    "tests/baselines/", "tests/meta_guards/",
    ".githooks/", ".husky/", ".github/workflows/",
)
# A case variant shadows the real pin file on case-insensitive filesystems.
_CASE_FOLDED_PIN_FILES: frozenset[str] = frozenset({"guard.lock", "scripts/guard"})


# PHP static-analysis / test / hook configuration, matched against the basename at any depth (R7).
PHP_QUALITY_CONFIG_RE: re.Pattern[str] = re.compile(
    r"phpstan[^/]*\.neon(?:\.dist)?|phpstan-baseline.*|\.?phpcs\.xml(?:\.dist)?|phpunit\.xml(?:\.dist)?"
    r"|psalm\.xml(?:\.dist)?|psalm-baseline\.xml|\.php-cs-fixer(?:\.dist)?\.php|phpmd\.xml|rector\.php|captainhook\.json"
)
_PHP_NON_CODE_SEGMENTS: frozenset[str] = frozenset({"vendor", "generated"})


def is_php_code_path(rel: str) -> bool:
    """`.php`/`.phtml` file outside any `vendor` or `generated` path segment."""
    segments = rel.split("/")
    return rel.endswith((".php", ".phtml")) and not _PHP_NON_CODE_SEGMENTS.intersection(segments[:-1])


def is_protected_governance_path(rel_path: str) -> bool:
    return (
        rel_path in PROTECTED_GOVERNANCE_FILES
        or PHP_QUALITY_CONFIG_RE.fullmatch(rel_path.rsplit("/", 1)[-1]) is not None
        or rel_path.startswith(PROTECTED_GOVERNANCE_PREFIXES)
        or rel_path.casefold() in _CASE_FOLDED_PIN_FILES
    )


NEW_2_1_SLOP_KINDS: frozenset[str] = frozenset({"domain_impurity", "excessive_nesting_depth", "query_mutation_side_effect"})
LEGACY_2_0_SLOP_KINDS: frozenset[str] = frozenset({
    "defensive_getattr_slop", "empty_subclass_alias", "excessive_parameter_list", "global_monkeypatch_state",
    "monkeypatch_binding", "nested_or_late_import", "passthrough_wrapper_bloat", "reexport_facade_aliasing",
    "swallowed_fallback_return", "symbol_alias_bloat",
})


def verify_commit_ref(ref: str, cwd: str | None = None) -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "--verify", f"{ref}^{{commit}}"], cwd=cwd, text=True, stderr=subprocess.PIPE).strip()
    except subprocess.CalledProcessError as exc:
        raise GuardAnalysisError(f"Cannot resolve commit ref '{ref}': {exc.stderr.strip() if exc.stderr else exc}") from exc


def git_cat_bytes(spec: str, cwd: str | None = None) -> bytes | None:
    """Blob bytes for `spec`, None when missing; reads through the active git_batch_session for this cwd if any."""
    reader = active_reader_for(cwd)
    if spec.startswith("HEAD:") and not (reader.head_exists() if reader is not None else head_commit_exists(cwd)):
        return None
    if reader is None or batch_unsafe(spec):
        return _git_cat_bytes_oneshot(spec, cwd)
    return reader.read_spec(spec)


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


ALLOWED_CONFIG_KEYS = frozenset({"extra_slop_rules", "legacy_loc_waivers", "import_roots", "self_skip", "languages", "frameworks", "php_paths", "php_suppression_exceptions", "magento_di_exceptions"})
PROFILE_VALUES = {"languages": frozenset({"php"}), "frameworks": frozenset({"magento"})}


def parse_guard_config_bytes(raw: bytes, source: str) -> dict[str, Any]:
    try:
        data = loads_bounded(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise GuardAnalysisError(f"Malformed audit_guard_config.json at {source}: {exc}") from exc
    if not isinstance(data, dict):
        raise GuardAnalysisError(f"audit_guard_config.json at {source} must be a JSON object")
    if unknown := sorted(set(data) - ALLOWED_CONFIG_KEYS):
        raise GuardAnalysisError(f"Unknown key(s) in audit_guard_config.json at {source}: {unknown}")
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
    fixtures = _parse_self_skip(data.get("self_skip", {}), source)
    languages, frameworks = _parse_profile(data, "languages", source), _parse_profile(data, "frameworks", source)
    if "magento" in frameworks and "php" not in languages:
        raise GuardAnalysisError(f"frameworks 'magento' requires languages 'php' in audit_guard_config.json at {source}")
    return {"extra_slop_rules": extra, "legacy_loc_waivers": waivers, "import_roots": roots, "fixture_paths": fixtures, "languages": languages, "frameworks": frameworks,
            "php_paths": validate_php_paths(data.get("php_paths", list(DEFAULT_PHP_PATHS)), source),
            "php_suppression_exceptions": validate_exceptions(data.get("php_suppression_exceptions", []), source),
            "magento_di_exceptions": validate_magento_exceptions(data.get("magento_di_exceptions", []), source)}


def _parse_profile(data: Mapping[str, Any], key: str, source: str) -> list[str]:
    values, known = data.get(key, []), PROFILE_VALUES[key]
    if not isinstance(values, list) or any(not isinstance(v, str) or v not in known for v in values) or len(set(values)) != len(values):
        raise GuardAnalysisError(f"Invalid {key} in audit_guard_config.json at {source}: need a list of unique values from {sorted(known)}")
    return list(values)


def _valid_fixture_path(entry: object) -> bool:
    if not isinstance(entry, str) or not entry.startswith(FIXTURE_PATH_PREFIX) or entry.endswith("/"):
        return False
    return clean_rel_segments(entry)


def _parse_self_skip(block: object, source: str) -> list[str]:
    if not isinstance(block, dict) or set(block) - {"fixture_paths"}:
        raise GuardAnalysisError(f"Invalid self_skip in audit_guard_config.json at {source}")
    paths = block.get("fixture_paths", [])
    if not isinstance(paths, list):
        raise GuardAnalysisError(f"self_skip.fixture_paths must be a list at {source}")
    for entry in paths:
        if not _valid_fixture_path(entry):
            raise GuardAnalysisError(f"Invalid self_skip.fixture_paths entry {entry!r} at {source}: need an exact tests/ file path")
    if len(set(paths)) != len(paths):
        raise GuardAnalysisError(f"Duplicate self_skip.fixture_paths entry at {source}")
    return list(paths)


def default_guard_config() -> dict[str, Any]:
    return {"extra_slop_rules": [], "legacy_loc_waivers": [], "import_roots": list(DEFAULT_IMPORT_ROOTS), "fixture_paths": [], "languages": [], "frameworks": [],
            "php_paths": list(DEFAULT_PHP_PATHS), "php_suppression_exceptions": [], "magento_di_exceptions": []}


def fixture_set(base_cfg: Mapping[str, Any] | None, target_cfg: Mapping[str, Any]) -> frozenset[str]:
    """Effective fixture exemptions: base AND target (an entry added in this change is still scanned); target alone without a base."""
    target = frozenset(target_cfg.get("fixture_paths", ()))
    return target if base_cfg is None else target & frozenset(base_cfg.get("fixture_paths", ()))


def load_guard_config_for_ref(ref_prefix: str, cwd: str | None = None) -> dict[str, Any]:
    cfg = external_config.active_override() or _read_guard_config_for_ref(ref_prefix, cwd)

    require_profile_capabilities(cfg)
    return cfg


def _read_guard_config_for_ref(ref_prefix: str, cwd: str | None) -> dict[str, Any]:
    rel = "scripts/audit/audit_guard_config.json"
    default_cfg = default_guard_config()
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


def _git_out(args: list[str], cwd: str | None) -> str | None:
    proc = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True)
    return proc.stdout.strip() if proc.returncode == 0 else None


def _distance_to_head(ref: str, cwd: str | None) -> int:
    out = _git_out(["rev-list", "--count", f"{ref}..HEAD"], cwd)
    return int(out) if out and out.isdigit() else _UNREACHABLE_DISTANCE


def default_remote_refs(cwd: str | None = None) -> list[str]:
    """Existing default-branch refs: the declared ``origin/HEAD`` first, then the others closest to HEAD first.

    A stale ``origin/master`` left behind after a rename to ``main`` is many commits behind HEAD, so it loses.
    """
    present = [ref for ref in DEFAULT_BRANCH_CANDIDATES if _git_out(["rev-parse", "--verify", "-q", f"{ref}^{{commit}}"], cwd)]
    declared = _git_out(["symbolic-ref", "-q", "--short", "refs/remotes/origin/HEAD"], cwd)
    return sorted(present, key=lambda ref: (ref != declared, _distance_to_head(ref, cwd), DEFAULT_BRANCH_CANDIDATES.index(ref)))


def trusted_base_candidates(cwd: str | None = None) -> list[str]:
    """CI-declared bases (MR target branch, push-before SHA), then the default remote refs; HEAD is never trusted."""
    ci_target = os.environ.get("CI_MERGE_REQUEST_TARGET_BRANCH_NAME")
    candidates: list[str] = [f"origin/{ci_target}"] if ci_target else []
    before_sha = os.environ.get("CI_COMMIT_BEFORE_SHA", "")
    if before_sha and set(before_sha) != {"0"}:
        candidates.append(before_sha)
    return [*candidates, *default_remote_refs(cwd)]


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


def _check_import_roots_monotonicity(base_roots: Sequence[str], target_roots: Sequence[str]) -> list[str]:
    # The resolver always includes DEFAULT_IMPORT_ROOTS, so only a dropped custom root narrows the graph.
    def norm(roots: Sequence[str]) -> list[str]:
        return [r.strip("/").strip() or "." for r in roots]
    kept = set(norm(target_roots)) | set(DEFAULT_IMPORT_ROOTS)
    removed = dict.fromkeys(r for r in norm(base_roots) if r not in kept)
    return [f"import_roots entry removed: '{r}' (narrows import-cycle detection)" for r in removed]


def verify_audit_guard_config_monotonicity(base_prefix: str, target_prefix: str, cwd: str | None = None) -> list[str]:
    if external_config.override_active():
        return []  # one operator-owned version of the config: nothing to compare
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
    errors.extend(_check_import_roots_monotonicity(b_cfg["import_roots"], t_cfg["import_roots"]))
    for key in ("languages", "frameworks"):
        errors.extend(f"{key} entry removed: '{v}' (narrows the analysis profile)" for v in b_cfg.get(key, []) if v not in t_cfg.get(key, []))
    kept_php = set(t_cfg.get("php_paths", DEFAULT_PHP_PATHS))
    errors.extend(f"php_paths entry removed: '{p}' (narrows PHP analysis scope)" for p in b_cfg.get("php_paths", DEFAULT_PHP_PATHS) if p not in kept_php)
    base_fixtures = set(b_cfg.get("fixture_paths", []))
    errors.extend(f"self_skip.fixture_paths entry added: '{p}' (widens the self-skip exemption)" for p in t_cfg.get("fixture_paths", []) if p not in base_fixtures)
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
        if status.startswith("D") or is_test_filename(new_path) or is_self_skipped(new_path, fixture_paths=NO_FIXTURES):  # fixtures filtered by caller / is_test_filename
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
            tree = parse_python(content, filename)
        except SyntaxError as exc:
            if strict:
                raise GuardAnalysisError(f"SyntaxError in test file {filename}:{exc.lineno or 1}: {exc.msg}") from exc
            return 0
        return visit_bounded(lambda: _count_ast_assertions(tree, multiplier=1), filename)
    if filename.endswith(JS_LIKE_EXTS):
        return _count_js_assertions(content)
    return 0


git_show_bytes = git_cat_bytes
