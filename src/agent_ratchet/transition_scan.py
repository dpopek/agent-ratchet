"""BASE/TARGET transition evaluation: per-entry slop, LOC, A2 topology, test tampering and commit ranges."""

from __future__ import annotations

import ast
from collections import Counter
import os
import re
import subprocess
from typing import Any, Mapping, Sequence

from agent_ratchet.ast_topology_guard import build_snapshot_import_graph, compare_import_cycles, extract_module_import_facts
from agent_ratchet.git_guard_io import (
    APP_CODE_PREFIXES, CODE_SCAN_EXTS, GuardAnalysisError, JS_LIKE_EXTS, NO_FIXTURES, SlopViolation, count_test_assertions,
    default_guard_config, diff_name_status, evaluate_loc_transition, fixture_set, git_cat_bytes, git_show_text, head_commit_exists,
    is_self_skipped, is_test_filename, list_snapshot_files, load_guard_config_for_ref,
    parse_python, visit_bounded, verify_audit_guard_config_monotonicity, verify_commit_ref,
)
from agent_ratchet.lock_policy import LOCK_PATH, adopted_guard_files, lock_check_is_local, verify_lock_transition
from agent_ratchet.php.scope import php_profile_active
from agent_ratchet.refactoring_guard import compare_ast_snapshots
from agent_ratchet.slop_text_scan import scan_diff_for_shortcut_escapes, scan_text_for_slop
from agent_ratchet.source_metrics import (
    _count_ast_assertions, _count_js_top_level_items, _find_balanced_span, _parametrize_multiplier, strip_js_comments,
)
from agent_ratchet.violation_dedupe import dedupe_php_violations


def _diff_unified_zero(base_ref: str | None, head_ref: str | None, cwd: str | None = None) -> str:
    cmd = ["git", "diff", "--cached", "-M", "-U0"] if head_ref is None else ["git", "diff", "-M", "-U0", str(base_ref), head_ref]
    try:
        return subprocess.check_output(cmd, cwd=cwd, text=True, stderr=subprocess.DEVNULL)
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        raise GuardAnalysisError(f"git diff -U0 failed: {exc}") from exc


_JS_ASSERT_RE = re.compile(r"\b(?:expect|assert)\s*(?:\(|\.)")
_JS_STRUCT_CALL_RE = re.compile(r"\.\s*(?:toEqual|toStrictEqual|toMatchObject)\s*\(")
_JS_TEST_HEAD_RE = re.compile(r"\b(?:it|test)\s*(\.each\s*\(\s*\[)?")
_JS_PRIMITIVE_ARG_RE = re.compile(r"^(?:[-+]?\d+(?:\.\d+)?n?|['\"`][\s\S]*['\"`]|true|false|null|undefined|NaN|Infinity)$")


def _is_py_struct_expr(expr: ast.expr) -> bool:
    if isinstance(expr, ast.Dict):
        return bool(expr.keys)
    if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
        return bool(expr.elts)
    if not isinstance(expr, ast.Call) or not (expr.args or expr.keywords):
        return False
    fn = expr.func.id if isinstance(expr.func, ast.Name) else (expr.func.attr if isinstance(expr.func, ast.Attribute) else "")
    return fn[:1].isupper() or fn == "dict"


def _is_py_struct_pair(left: ast.expr, right: ast.expr, struct_names: set[str]) -> bool:
    lit_t = (ast.Dict, ast.List, ast.Tuple, ast.Set)
    if isinstance(left, ast.Constant) or isinstance(right, ast.Constant) or (isinstance(left, lit_t) and isinstance(right, lit_t)) or ast.dump(left) == ast.dump(right):
        return False
    return any(_is_py_struct_expr(s) or (isinstance(s, ast.Name) and s.id in struct_names) for s in (left, right))


def _count_fn_py_struct_eqs(fn_node: ast.AST) -> int:
    struct_names = {t.id for n in ast.walk(fn_node) if isinstance(n, ast.Assign) and _is_py_struct_expr(n.value) for t in n.targets if isinstance(t, ast.Name)}
    eqs = 0
    for n in ast.walk(fn_node):
        if isinstance(n, ast.Assert) and isinstance(n.test, ast.Compare) and len(n.test.ops) == 1 and isinstance(n.test.ops[0], ast.Eq):
            eqs += int(_is_py_struct_pair(n.test.left, n.test.comparators[0], struct_names))
        elif isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in ("assertEqual", "assertDictEqual", "assertListEqual") and len(n.args) >= 2:
            eqs += int(_is_py_struct_pair(n.args[0], n.args[1], struct_names))
    return eqs


def _collect_py_test_funcs(body: list[ast.stmt], prefix: str = "") -> dict[str, tuple[int, int, int]]:
    funcs: dict[str, tuple[int, int, int]] = {}
    for stmt in body:
        if isinstance(stmt, ast.ClassDef):
            funcs.update(_collect_py_test_funcs(stmt.body, f"{prefix}{stmt.name}."))
        elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)) and stmt.name.startswith("test_"):
            m = _parametrize_multiplier(stmt)
            funcs[f"{prefix}{stmt.name}"] = (m, _count_ast_assertions(stmt, m), m * _count_fn_py_struct_eqs(stmt))
    return funcs


def _allows_py_dto_consolidation(old_path: str, new_path: str, b_txt: str, t_txt: str, b_cnt: int, t_cnt: int) -> bool:
    b_tree, t_tree = parse_python(b_txt, old_path), parse_python(t_txt, new_path)
    b_funcs = visit_bounded(lambda: _collect_py_test_funcs(b_tree.body), old_path)
    t_funcs = visit_bounded(lambda: _collect_py_test_funcs(t_tree.body), new_path)
    b_other, t_other = b_cnt - sum(a for _, a, _ in b_funcs.values()), t_cnt - sum(a for _, a, _ in t_funcs.values())
    if not b_funcs or t_other < b_other or not (set(b_funcs) <= set(t_funcs)) or any(ta < tm or tm < 1 for tm, ta, _ in t_funcs.values()):
        return False
    return all(t_funcs[k][0] >= bm and (t_funcs[k][1] >= ba or t_funcs[k][2] >= t_funcs[k][0]) for k, (bm, ba, _) in b_funcs.items())


def _is_js_struct_arg(arg: str) -> bool:
    s = arg.strip()
    if not s:
        return False
    if s[0] in "{[":
        return s[-1] == ("}" if s[0] == "{" else "]") and bool(s[1:-1].strip())
    return not _JS_PRIMITIVE_ARG_RE.match(s)


def _count_js_body_struct_eqs(body: str) -> int:
    total = 0
    for m in _JS_STRUCT_CALL_RE.finditer(body):
        end = _find_balanced_span(body, m.end() - 1, "(", ")")
        if end != -1 and _is_js_struct_arg(body[m.end() : end]):
            total += 1
    return total


def _extract_single_js_block(clean: str, match: re.Match[str]) -> tuple[str, int, int, int] | None:
    if match.group(1):
        arr_close = _find_balanced_span(clean, match.end() - 1, "[", "]")
        mult = _count_js_top_level_items(clean[match.end() : arr_close]) if arr_close != -1 else 0
        call_open = clean.find("(", arr_close + 1) if mult >= 1 else -1
    else:
        m_open = re.match(r"\s*\(", clean[match.end() :])
        if not m_open:
            return ("", 0, 0, 0)
        mult, call_open = 1, match.end() + m_open.end() - 1
    call_close = _find_balanced_span(clean, call_open, "(", ")") if call_open != -1 else -1
    inner = clean[call_open + 1 : call_close] if call_close != -1 else ""
    m_title = re.match(r"\s*(['\"`])(.*?)\1", inner)
    if not m_title:
        return None
    b_open = inner.find("{", m_title.end())
    b_close = _find_balanced_span(inner, b_open, "{", "}") if b_open != -1 else -1
    body = inner[b_open + 1 : b_close] if b_close != -1 else inner[m_title.end() :]
    return (m_title.group(2), mult, mult * len(_JS_ASSERT_RE.findall(body)), mult * _count_js_body_struct_eqs(body))


def _collect_js_test_blocks(src: str) -> list[tuple[str, int, int, int]] | None:
    clean = strip_js_comments(src)
    blocks: list[tuple[str, int, int, int]] = []
    for m in _JS_TEST_HEAD_RE.finditer(clean):
        blk = _extract_single_js_block(clean, m)
        if blk is None:
            return None
        if blk[1] > 0:
            blocks.append(blk)
    return blocks


def _allows_js_dto_consolidation(b_txt: str, t_txt: str, b_cnt: int, t_cnt: int) -> bool:
    b_blocks, t_blocks = _collect_js_test_blocks(b_txt), _collect_js_test_blocks(t_txt)
    if not b_blocks or not t_blocks or len(t_blocks) < len(b_blocks) or any(a < m or m < 1 for _, m, a, _ in t_blocks):
        return False
    if t_cnt - sum(a for _, _, a, _ in t_blocks) < b_cnt - sum(a for _, _, a, _ in b_blocks):
        return False
    b_map: dict[str, list[tuple[int, int, int]]] = {}
    t_map: dict[str, list[tuple[int, int, int]]] = {}
    for title, m, a, s in b_blocks:
        b_map.setdefault(title, []).append((m, a, s))
    for title, m, a, s in t_blocks:
        t_map.setdefault(title, []).append((m, a, s))
    return all(len(t_map.get(k, ())) >= len(v) and all(tm >= bm and (ta >= ba or ts >= tm) for (bm, ba, _), (tm, ta, ts) in zip(v, t_map[k])) for k, v in b_map.items())


def _allows_dto_consolidation(b_txt: str, old_path: str, t_txt: str, new_path: str, b_cnt: int, t_cnt: int) -> bool:
    if t_cnt < 1 or any(v.category in ("empty_dummy_test", "tautological_assertion") for v in scan_text_for_slop(t_txt, new_path)):
        return False
    if new_path.endswith(".py") and old_path.endswith(".py"):
        return _allows_py_dto_consolidation(old_path, new_path, b_txt, t_txt, b_cnt, t_cnt)
    if new_path.endswith(JS_LIKE_EXTS) and old_path.endswith(JS_LIKE_EXTS):
        return _allows_js_dto_consolidation(b_txt, t_txt, b_cnt, t_cnt)
    return False


def _check_transition_test_tampering(entries: list[tuple[str, str, str]], base_prefix: str, target_prefix: str, cwd: str | None = None) -> list[SlopViolation]:
    allow_delete = os.environ.get("ALLOW_TEST_DELETION") == "1"
    allow_reduction = os.environ.get("ALLOW_ASSERTION_REDUCTION") == "1"
    total_base, total_target = 0, 0
    deleted_files: list[str] = []
    reduced_files: list[tuple[str, int, int]] = []
    deleted_tests = [old for st, old, _ in entries if st.startswith("D") and is_test_filename(old)]
    retired = adopted_guard_files(base_prefix, target_prefix, deleted_tests, cwd=cwd) if deleted_tests else frozenset()
    for status, old_path, new_path in entries:
        old_is_test, new_is_test = is_test_filename(old_path), is_test_filename(new_path)
        if (not old_is_test and not new_is_test) or (status.startswith("D") and old_path in retired):
            continue
        b_txt = git_show_text(f"{base_prefix}:{old_path}", cwd) if (old_is_test and not status.startswith("A")) else None
        t_txt = git_show_text(f"{target_prefix}:{new_path}" if target_prefix else f":{new_path}", cwd) if (new_is_test and not status.startswith("D")) else None
        b_cnt = count_test_assertions(b_txt, old_path, strict=True) if b_txt is not None else 0
        t_cnt = count_test_assertions(t_txt, new_path, strict=True) if t_txt is not None else 0
        if status.startswith("D") and old_is_test:
            total_base += b_cnt
            deleted_files.append(old_path)
        elif t_cnt < b_cnt and b_txt is not None and t_txt is not None and _allows_dto_consolidation(b_txt, old_path, t_txt, new_path, b_cnt, t_cnt):
            total_base += t_cnt
            total_target += t_cnt
        else:
            total_base += b_cnt
            total_target += t_cnt
            if t_cnt < b_cnt:
                reduced_files.append((new_path, b_cnt, t_cnt))

    violations: list[SlopViolation] = []
    if deleted_files and not allow_delete and total_target < total_base:
        for rel_path in deleted_files:
            violations.append(SlopViolation(rel_path, 1, "test_file_deleted", "Deleting test files with net assertion loss is blocked by Test Tamper Guard (set ALLOW_TEST_DELETION=1 if intentional).", f"Deleted: {rel_path} (net assertions: {total_base} -> {total_target})"))
    if reduced_files and not allow_reduction and total_target < total_base:
        for rel_path, b_cnt, t_cnt in reduced_files:
            violations.append(SlopViolation(rel_path, 1, "test_assertion_reduction", f"Assertion count decreased in {rel_path}: {b_cnt} -> {t_cnt} (changeset net: {total_base} -> {total_target}).", f"assertions: {b_cnt} -> {t_cnt}"))
    return violations


def _new_or_worsened_text_slop(base_txt: str | None, target_txt: str, new_path: str, extra_rules: Sequence[Mapping[str, Any]]) -> list[SlopViolation]:
    target_v = scan_text_for_slop(target_txt, new_path, extra_rules=extra_rules)
    if base_txt is None or not target_v:
        return target_v
    budget = Counter((v.category, v.snippet) for v in scan_text_for_slop(base_txt, new_path, extra_rules=extra_rules))
    added: list[SlopViolation] = []
    for v in target_v:
        key = (v.category, v.snippet)
        if budget[key] > 0:
            budget[key] -= 1
        else:
            added.append(v)
    return added


def _load_python_snapshot_files(ref_prefix: str, cwd: str | None = None) -> dict[str, str]:
    out: dict[str, str] = {}
    for rel in list_snapshot_files(ref_prefix, cwd=cwd):
        if rel.endswith(".py") and rel.startswith(APP_CODE_PREFIXES) and not is_test_filename(rel) and not is_self_skipped(rel, fixture_paths=NO_FIXTURES):  # fixtures filtered by caller / is_test_filename
            txt = git_show_text(f"{ref_prefix}:{rel}" if ref_prefix else f":{rel}", cwd=cwd)
            if txt is not None:
                out[rel] = txt
    return out


def _py_entry_needs_a2(status: str, old_path: str, new_path: str, base_txt: str | None, target_txt: str) -> bool:
    if not (new_path.startswith(APP_CODE_PREFIXES) or old_path.startswith(APP_CODE_PREFIXES)) or is_test_filename(new_path):
        return False
    if status.startswith(("A", "R", "C")) or base_txt is None:
        return True
    try:
        bf, tf = extract_module_import_facts(base_txt, old_path), extract_module_import_facts(target_txt, new_path)
        return bf.raw_imports != tf.raw_imports or bf.defined_attrs != tf.defined_attrs or bf.has_dynamic_exports != tf.has_dynamic_exports
    except GuardAnalysisError as exc:
        if isinstance(exc.__cause__, SyntaxError):
            return False
        raise


def _evaluate_entry_transition(
    status: str, old_path: str, new_path: str, base_ref: str, target_prefix: str, cwd: str | None,
    extra_rules: Sequence[Mapping[str, Any]], waivers: Sequence[Mapping[str, Any]], loc_ceilings: dict[str, int] | None, check_step_loc: bool, fixture_paths: frozenset[str],
) ->tuple[list[SlopViolation], bool]:
    if status.startswith("D"):
        if loc_ceilings is not None:
            loc_ceilings.pop(old_path, None)
        return [], old_path.endswith(".py") and old_path.startswith(APP_CODE_PREFIXES)
    if is_self_skipped(new_path, fixture_paths=fixture_paths):
        return [], False
    t_spec = f"{target_prefix}:{new_path}" if target_prefix else f":{new_path}"
    target_bytes = git_cat_bytes(t_spec, cwd)
    if target_bytes is None:
        raise GuardAnalysisError(f"Unable to read target git blob '{t_spec}'")
    base_bytes = None if status.startswith("A") else git_cat_bytes(f"{base_ref}:{old_path}", cwd)
    violations: list[SlopViolation] = []
    if not is_test_filename(new_path) and check_step_loc:
        loc_v, new_ceil = evaluate_loc_transition(new_path, status, base_bytes, target_bytes, waivers=waivers)
        violations.extend(loc_v)
        if loc_ceilings is not None:
            if old_path != new_path:
                loc_ceilings.pop(old_path, None)
            loc_ceilings[new_path] = new_ceil
    if not new_path.endswith(CODE_SCAN_EXTS):
        return violations, False
    target_txt = target_bytes.decode("utf-8", errors="replace")
    base_txt = base_bytes.decode("utf-8", errors="replace") if base_bytes is not None else None
    violations.extend(_new_or_worsened_text_slop(base_txt, target_txt, new_path, extra_rules))
    if not new_path.endswith(".py"):
        return violations, False
    violations.extend(compare_ast_snapshots(base_txt, target_txt, new_path, extra_rules=extra_rules))
    return violations, _py_entry_needs_a2(status, old_path, new_path, base_txt, target_txt)


def _evaluate_transition(
    base_ref: str, target_ref: str | None, cwd: str | None = None, loc_ceilings: dict[str, int] | None = None,
    check_step_loc: bool = True,
) -> list[SlopViolation]:
    target_prefix = target_ref or ""
    has_base = base_ref != "HEAD" or head_commit_exists(cwd)
    base_cfg = load_guard_config_for_ref(base_ref, cwd=cwd) if has_base else default_guard_config()
    cfg = load_guard_config_for_ref(target_prefix, cwd=cwd)
    fixtures = fixture_set(base_cfg if has_base else None, cfg)
    entries = diff_name_status(base_ref, target_ref, cwd=cwd)
    diff_text = _diff_unified_zero(base_ref, target_ref, cwd=cwd)
    violations: list[SlopViolation] = []
    if has_base:
        for cfg_err in verify_audit_guard_config_monotonicity(base_ref, target_prefix, cwd=cwd):
            violations.append(SlopViolation("scripts/audit/audit_guard_config.json", 1, "modified_file_loc_buffer", cfg_err, cfg_err[:100]))
        for lock_err in verify_lock_transition(base_ref, target_prefix, cwd=cwd, local=lock_check_is_local(target_ref)):
            violations.append(SlopViolation(LOCK_PATH, 1, "unjustified_lint_escape", lock_err, lock_err[:100]))
    should_run_a2 = tuple(base_cfg["import_roots"]) != tuple(cfg["import_roots"])
    for status, old_path, new_path in entries:
        entry_v, a2_flag = _evaluate_entry_transition(status, old_path, new_path, base_ref, target_prefix, cwd, cfg["extra_slop_rules"], cfg["legacy_loc_waivers"], loc_ceilings, check_step_loc, fixtures)
        violations.extend(entry_v)
        should_run_a2 = should_run_a2 or a2_flag
    if should_run_a2 and not any(v.category == "syntax_error" for v in violations):
        base_g = build_snapshot_import_graph(_load_python_snapshot_files(base_ref, cwd=cwd), import_roots=base_cfg["import_roots"])
        target_g = build_snapshot_import_graph(_load_python_snapshot_files(target_prefix, cwd=cwd), import_roots=cfg["import_roots"])
        violations.extend(compare_import_cycles(base_g, target_g, rename_map={old_p: new_p for st, old_p, new_p in entries if st.startswith("R")}))
    if diff_text:
        violations.extend(scan_diff_for_shortcut_escapes(diff_text, fixture_paths=fixtures))
    violations.extend(_check_transition_test_tampering(entries, base_ref, target_prefix, cwd=cwd))
    if php_profile_active(cfg):
        from agent_ratchet.php.scan import php_transition_violations
        violations.extend(php_transition_violations(entries, base_ref, target_prefix, base_cfg, cfg, cwd=cwd))
    if "magento" in cfg.get("frameworks", ()):
        from agent_ratchet.magento.scan import magento_transition_violations
        violations.extend(magento_transition_violations(entries, base_ref, target_prefix, base_cfg, cfg, cwd=cwd))
    return violations


def _check_aggregate_range_loc(base_sha: str, head_sha: str, loc_ceilings: dict[str, int], cwd: str | None) -> list[SlopViolation]:
    out: list[SlopViolation] = []
    for status, old_path, new_path in diff_name_status(base_sha, head_sha, cwd=cwd):
        if status.startswith("D") or is_test_filename(new_path) or is_self_skipped(new_path, fixture_paths=NO_FIXTURES):  # fixtures filtered by is_test_filename
            continue
        t_bytes = git_cat_bytes(f"{head_sha}:{new_path}", cwd)
        if t_bytes is None:
            continue
        b_bytes = None if status.startswith("A") else git_cat_bytes(f"{base_sha}:{old_path}", cwd)
        range_v, _ = evaluate_loc_transition(new_path, status, b_bytes, t_bytes, waivers=(), ceiling_override=loc_ceilings.get(new_path))
        out.extend(v._replace(message=f"Aggregate range: {v.message}") for v in range_v)
    return out


def _evaluate_commit_range(range_spec: str, cwd: str | None = None) -> list[SlopViolation]:
    if ".." not in range_spec:
        raise GuardAnalysisError(f"Invalid --commit-range '{range_spec}'; expected <base>..<head>.")
    raw_base, raw_head = range_spec.split("..", 1)
    base_sha, head_sha = verify_commit_ref(raw_base, cwd=cwd), verify_commit_ref(raw_head, cwd=cwd)
    commits = subprocess.check_output(["git", "rev-list", "--reverse", f"{base_sha}..{head_sha}"], cwd=cwd, text=True).splitlines()
    loc_ceilings: dict[str, int] = {}
    violations: list[SlopViolation] = []
    for commit_sha in commits:
        parents = subprocess.check_output(["git", "rev-list", "--parents", "-n", "1", commit_sha], cwd=cwd, text=True).strip().split()[1:]
        if len(parents) == 1:
            violations.extend(_evaluate_transition(parents[0], commit_sha, cwd=cwd, loc_ceilings=loc_ceilings, check_step_loc=True))
        elif len(parents) > 1:
            for p in parents:
                violations.extend(SlopViolation("scripts/audit/audit_guard_config.json", 1, "modified_file_loc_buffer", e, e[:100]) for e in verify_audit_guard_config_monotonicity(p, commit_sha, cwd=cwd))
                violations.extend(SlopViolation(LOCK_PATH, 1, "unjustified_lint_escape", e, e[:100]) for e in verify_lock_transition(p, commit_sha, cwd=cwd, local=lock_check_is_local(commit_sha)))
    violations.extend(_evaluate_transition(base_sha, head_sha, cwd=cwd, loc_ceilings=None, check_step_loc=False))
    violations.extend(_check_aggregate_range_loc(base_sha, head_sha, loc_ceilings, cwd))
    return dedupe_php_violations(violations)
