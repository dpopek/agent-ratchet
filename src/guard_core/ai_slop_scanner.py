#!/usr/bin/env python3
"""Git-blob-isolated AST, topology (A2), regex, and diff scanner (GUARD_VERSION = "2.3.3")."""

from __future__ import annotations

import argparse
import ast
from collections import Counter
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any, Mapping, Sequence

from guard_core.git_guard_io import (
    APP_CODE_PREFIXES, CODE_SCAN_EXTS, JS_LIKE_EXTS,
    SELF_SKIP_NAMES, GuardAnalysisError as GuardAnalysisError,
    SlopViolation as SlopViolation, check_staged_file_size_buffer as check_staged_file_size_buffer,
    count_test_assertions as count_test_assertions, diff_name_status,
    evaluate_loc_transition, git_cat_bytes, git_show_text, head_commit_exists, is_test_filename,
    list_snapshot_files, load_guard_config_for_ref,
    verify_audit_guard_config_monotonicity, verify_commit_ref,
)
from guard_core.lock_policy import LOCK_PATH, adopted_guard_files, check_staged_lock, lock_check_is_local, verify_lock_transition
from guard_core.source_metrics import (
    _count_ast_assertions, _count_js_top_level_items, _find_balanced_span, _parametrize_multiplier, strip_js_comments,
)

from guard_core.ast_topology_guard import build_snapshot_import_graph, compare_import_cycles, extract_module_import_facts
from guard_core.refactoring_guard import compare_ast_snapshots, scan_ast_for_refactoring_slop as scan_ast_for_refactoring_slop

__all__ = [
    "GuardAnalysisError", "SlopViolation", "check_staged_file_size_buffer", "check_staged_test_tampering",
    "count_test_assertions", "load_worktree_guard_config", "scan_ast_for_refactoring_slop",
    "scan_diff_for_shortcut_escapes", "scan_text_for_slop",
]

CONVERSATIONAL_PATTERNS = [(
    re.compile(
        r"(?i)\b(as an ai language model|certainly[!,]|here is the implementation|"
        r"i hope this helps|let me know if you need anything else|here's the complete code|"
        r"in this updated version|sure thing[!,]|feel free to ask)\b"
    ),
    "conversational_marker", "AI conversational leftover / monologue marker detected",
)]

TAUTOLOGICAL_PATTERNS = [
    (re.compile(r"\bassert\s+(?:True|1\s*==\s*1|not\s+False)\b"), "tautological_assertion", "Tautological Python assertion detected (e.g. assert True or assert 1 == 1)"),
    (re.compile(r"expect\(\s*(?:true\s*\)\.toBe\(\s*true|1\s*\)\.toBe\(\s*1|false\s*\)\.toBe\(\s*false|true\s*\)\.toBeTruthy\(\s*)\)"), "tautological_assertion", "Tautological Jest/Vitest assertion detected (e.g. expect(true).toBe(true))"),
    (re.compile(r"def\s+test_[a-zA-Z0-9_]+\s*\([^)]*\)\s*:\s*(?:pass|\.\.\.)(?:\s*#.*)?$", re.MULTILINE), "empty_dummy_test", "Empty dummy test body with only pass / ... detected"),
    (
        re.compile(
            r"\b(?:it|test)(?:\s*\.each\s*\([^)]*\))?\s*\(\s*(['\"`]).*?\1\s*,\s*"
            r"(?:async\s+)?(?:function\b\s*\([^)]*\)|(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>)\s*"
            r"\{\s*(?://[^\n]*\s*|/\*[\s\S]*?\*/\s*)*\}"
        ),
        "empty_dummy_test", "Empty JS/TS test block with no assertions detected",
    ),
]

ANTI_HACK_PATTERNS = [(
    re.compile(r"get\s+[a-zA-Z0-9_$]+\s*\(\)\s*\{\s*throw\b"),
    "synthetic_throwing_getter",
    "Synthetic throwing getter detected in test input! Test authentic I/O or malformed payloads instead of breaking prototype getters.",
)]

SKIP_ESCAPE_RE = re.compile(
    r"(?:@pytest\.mark\.(?:skip|xfail)\b|\bpytest\.(?:skip|xfail)\s*\(|@unittest\.skip\b|"
    r"\b(?:it|test|describe)\.(?:skip|only|todo)\s*\(|\b(?:xit|xdescribe)\s*\()"
)

TS_NOCHECK_RE = re.compile(r"@ts-nocheck\b")

SUPPRESSOR_DETECT_RE = re.compile(
    r"(?:#\s*noqa\b|#\s*type:\s*ignore\b|@ts-ignore\b|@ts-expect-error\b|eslint-disable(?:-next-line|-line)?\b)"
)

JUSTIFIED_SUPPRESSOR_PATTERNS = [
    re.compile(r"#\s*noqa:\s*[A-Z0-9,\s]+\s+--\s+\S.{4,}"),
    re.compile(r"#\s*type:\s*ignore\[[a-zA-Z0-9_,\s-]+\]\s+--\s+\S.{4,}"),
    re.compile(r"@ts-(?:ignore|expect-error)(?:\s+TS\d+)?\s+--\s+\S.{7,}"),
    re.compile(r"eslint-disable(?:-next-line|-line)?\s+[a-zA-Z0-9_/@,\s-]+\s+--\s+\S.{4,}"),
]

TASK_NOMENCLATURE_RE: re.Pattern[str] = re.compile(
    r"(?i)(?<![a-z0-9])(?:wave[_\s-]*\d+|phase[_\s-]*\d+[a-z]?|def-\d+|fix_v\d+|v\d+_final|path_[ab]_audit)(?![a-z0-9])"
)

EVASION_COMMENT_RE: re.Pattern[str] = re.compile(
    r"(?i)(?:without calling the forbidden|"
    r"bypass(?:ing)?\s+(?:the\s+)?(?:ratchet|ceiling|(?:loc|complexity|size)\s+limit|"
    r"(?:architecture|architectural|boundary)\s+(?:guard|rule|test)|lint(?:er)?)|"
    r"avoid\s+circular\s+import|alias\s+for\s+backward\s+compatibility)"
)


def _scan_extra_rules(
    lines: list[str],
    filename: str,
    is_test: bool,
    extra_rules: Sequence[Mapping[str, Any]],
) -> list[SlopViolation]:
    out: list[SlopViolation] = []
    for rule in extra_rules:
        if rule.get("test_only", False) and not is_test:
            continue
        pat = re.compile(str(rule["pattern"]))
        for lineno, line in enumerate(lines, 1):
            if pat.search(line):
                out.append(SlopViolation(filename, lineno, str(rule["category"]), str(rule["message"]), line.strip()[:100]))
    return out


def _scan_code_specific_slop(
    text: str,
    lines: list[str],
    filename: str,
    extra_rules: Sequence[Mapping[str, Any]],
) -> list[SlopViolation]:
    violations: list[SlopViolation] = []
    is_test = is_test_filename(filename)
    for lineno, line in enumerate(lines, 1):
        if TS_NOCHECK_RE.search(line):
            violations.append(SlopViolation(filename, lineno, "unjustified_lint_escape", "File-wide @ts-nocheck is forbidden; fix types locally.", line.strip()[:100]))
        for pattern, category, message in TAUTOLOGICAL_PATTERNS:
            if category == "tautological_assertion" and pattern.search(line):
                violations.append(SlopViolation(filename, lineno, category, message, line.strip()[:100]))
    if is_test or filename.endswith(".py"):
        for pattern, category, message in TAUTOLOGICAL_PATTERNS:
            if category == "empty_dummy_test":
                for match in pattern.finditer(text):
                    lineno = text[: match.start()].count("\n") + 1
                    violations.append(SlopViolation(filename, lineno, category, message, match.group(0).strip()[:100]))
    if is_test:
        for pattern, category, message in ANTI_HACK_PATTERNS:
            for match in pattern.finditer(text):
                lineno = text[: match.start()].count("\n") + 1
                snip = match.group(0).strip().replace("\n", " ")[:100]
                violations.append(SlopViolation(filename, lineno, category, message, snip))
    violations.extend(_scan_extra_rules(lines, filename, is_test, extra_rules))
    return violations


def scan_text_for_slop(text: str, filename: str, extra_rules: Sequence[Mapping[str, Any]] = ()) -> list[SlopViolation]:
    violations: list[SlopViolation] = []
    lines = text.splitlines()
    for lineno, line in enumerate(lines, 1):
        for pattern, category, message in CONVERSATIONAL_PATTERNS:
            if pattern.search(line):
                violations.append(SlopViolation(filename, lineno, category, message, line.strip()[:100]))
        if EVASION_COMMENT_RE.search(line):
            violations.append(SlopViolation(filename, lineno, "guard_evasion_comment", "Comment explicitly admits bypassing architectural/ratchet guard (Zero-S2/S6).", line.strip()[:100]))
    if filename.endswith(CODE_SCAN_EXTS):
        violations.extend(_scan_code_specific_slop(text, lines, filename, extra_rules))
    return violations


def _is_justified_suppressor(line: str) -> bool:
    return any(p.search(line) for p in JUSTIFIED_SUPPRESSOR_PATTERNS)


def _check_added_diff_line(current_file: str, lineno: int, added_line: str) -> list[SlopViolation]:
    out: list[SlopViolation] = []
    snip = added_line.strip()[:100]
    if SKIP_ESCAPE_RE.search(added_line):
        out.append(SlopViolation(current_file, lineno, "test_skip_escape", "Forbidden test skip/xfail/only added in diff! Fix the underlying issue.", snip))
    if TS_NOCHECK_RE.search(added_line):
        out.append(SlopViolation(current_file, lineno, "unjustified_lint_escape", "File-wide @ts-nocheck is forbidden; fix types locally.", snip))
    elif SUPPRESSOR_DETECT_RE.search(added_line) and not _is_justified_suppressor(added_line):
        out.append(SlopViolation(current_file, lineno, "unjustified_lint_escape", "Suppressor directive requires explicit rule code and '-- <reason>'.", snip))
    if TASK_NOMENCLATURE_RE.search(added_line):
        out.append(SlopViolation(current_file, lineno, "task_nomenclature_leak", "Task/session nomenclature (Wave, Phase, DEF-xxx, fix_v2) is forbidden in code/comments (Zero-S5).", snip))
    if EVASION_COMMENT_RE.search(added_line):
        out.append(SlopViolation(current_file, lineno, "guard_evasion_comment", "Comment explicitly admits bypassing architectural/ratchet guard (Zero-S2/S6).", snip))
    return out


def scan_diff_for_shortcut_escapes(diff_text: str) -> list[SlopViolation]:
    violations: list[SlopViolation] = []
    current_file, lineno = "", 0
    for raw_line in diff_text.splitlines():
        if raw_line.startswith("+++ b/"):
            current_file, lineno = raw_line[6:].strip(), 0
        elif raw_line.startswith("@@ "):
            m = re.search(r"\+(\d+)", raw_line)
            lineno = int(m.group(1)) - 1 if m else 0
        elif not current_file or os.path.basename(current_file) in SELF_SKIP_NAMES or not current_file.endswith(CODE_SCAN_EXTS):
            continue
        elif raw_line.startswith("+") and not raw_line.startswith("+++"):
            lineno += 1
            violations.extend(_check_added_diff_line(current_file, lineno, raw_line[1:]))
        elif not raw_line.startswith("-"):
            lineno += 1
    return violations


def load_worktree_guard_config(cwd: str | None = None) -> dict[str, Any]:
    return load_guard_config_for_ref("WORKTREE", cwd=cwd)


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


def _allows_py_dto_consolidation(b_txt: str, t_txt: str, b_cnt: int, t_cnt: int) -> bool:
    b_funcs = _collect_py_test_funcs(ast.parse(b_txt).body)
    t_funcs = _collect_py_test_funcs(ast.parse(t_txt).body)
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
        return _allows_py_dto_consolidation(b_txt, t_txt, b_cnt, t_cnt)
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


def check_staged_test_tampering(cwd: str | None = None) -> list[SlopViolation]:
    return _check_transition_test_tampering(diff_name_status(None, None, cwd=cwd), "HEAD", "", cwd=cwd)


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
        if rel.endswith(".py") and rel.startswith(APP_CODE_PREFIXES) and not is_test_filename(rel) and os.path.basename(rel) not in SELF_SKIP_NAMES:
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
    except GuardAnalysisError:
        return False


def _evaluate_entry_transition(
    status: str, old_path: str, new_path: str, base_ref: str, target_prefix: str, cwd: str | None,
    extra_rules: Sequence[Mapping[str, Any]], waivers: Sequence[Mapping[str, Any]], loc_ceilings: dict[str, int] | None, check_step_loc: bool,
) -> tuple[list[SlopViolation], bool]:
    if status.startswith("D"):
        if loc_ceilings is not None:
            loc_ceilings.pop(old_path, None)
        return [], old_path.endswith(".py") and old_path.startswith(APP_CODE_PREFIXES)
    if os.path.basename(new_path) in SELF_SKIP_NAMES:
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
    base_cfg = load_guard_config_for_ref(base_ref, cwd=cwd) if has_base else {"extra_slop_rules": [], "legacy_loc_waivers": [], "import_roots": [".", "src", "backend", "web", "mobile", "packages"]}
    cfg = load_guard_config_for_ref(target_prefix, cwd=cwd)
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
        entry_v, a2_flag = _evaluate_entry_transition(status, old_path, new_path, base_ref, target_prefix, cwd, cfg["extra_slop_rules"], cfg["legacy_loc_waivers"], loc_ceilings, check_step_loc)
        violations.extend(entry_v)
        should_run_a2 = should_run_a2 or a2_flag
    if should_run_a2 and not any(v.category == "syntax_error" for v in violations):
        base_g = build_snapshot_import_graph(_load_python_snapshot_files(base_ref, cwd=cwd), import_roots=base_cfg["import_roots"])
        target_g = build_snapshot_import_graph(_load_python_snapshot_files(target_prefix, cwd=cwd), import_roots=cfg["import_roots"])
        violations.extend(compare_import_cycles(base_g, target_g, rename_map={old_p: new_p for st, old_p, new_p in entries if st.startswith("R")}))
    if diff_text:
        violations.extend(scan_diff_for_shortcut_escapes(diff_text))
    violations.extend(_check_transition_test_tampering(entries, base_ref, target_prefix, cwd=cwd))
    return violations


def _check_aggregate_range_loc(base_sha: str, head_sha: str, loc_ceilings: dict[str, int], cwd: str | None) -> list[SlopViolation]:
    out: list[SlopViolation] = []
    for status, old_path, new_path in diff_name_status(base_sha, head_sha, cwd=cwd):
        if status.startswith("D") or is_test_filename(new_path) or os.path.basename(new_path) in SELF_SKIP_NAMES:
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
    return violations


def run_fixtures_self_test() -> bool:
    dirty_fixture = (
        "// Certainly! Here is the implementation:\n"
        "const payload = { get event() { throw new Error('boom'); } };\n"
        "expect(true).toBe(true);\n"
        "def test_stub(): pass\n"
    )
    clean_fixture = "const title = res.cardsV2[0].card.header.title;\nexpect(title).toBe('Expected Title');\n"
    assert len(scan_text_for_slop(dirty_fixture, "fixture_dirty.test.js")) >= 4
    assert len(scan_text_for_slop(clean_fixture, "fixture_clean.test.js")) == 0
    diff_dirty = "+++ b/tests/test_x.py\n+@pytest.mark.skip\n+x = 1  # noqa\n+# Wave 5 fix_v2\n"
    diff_clean = "+++ b/tests/test_x.py\n+x = 1  # noqa: E501 -- valid reason here\n"
    assert len(scan_diff_for_shortcut_escapes(diff_dirty)) >= 3
    assert len(scan_diff_for_shortcut_escapes(diff_clean)) == 0
    ast_dirty = "_default_factory = None\ndef bad(a, b, c, d, e, f):\n    from src.x import _priv\n    return getattr(a, 'k', None)\n"
    assert len(scan_ast_for_refactoring_slop(ast_dirty, "src/domain/sample.py")) >= 4
    print("✅ ai_slop_scanner fixtures self-test passed.")
    return True


_SKIP_SCAN_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", ".next", "coverage"}


def _resolve_scan_targets(args: argparse.Namespace) -> list[Path]:
    targets: list[Path] = []
    roots = args.files if args.files else [f for f in ("src", "backend", "web", "mobile", "packages", "test", "tests") if Path(f).exists()]
    for f in roots:
        p = Path(f)
        if p.is_dir():
            for ext in tuple(f"*{e}" for e in CODE_SCAN_EXTS):
                targets.extend(cand for cand in p.rglob(ext) if not any(part in _SKIP_SCAN_DIRS for part in cand.parts))
        elif p.exists():
            targets.append(p)
    return targets


def _scan_worktree_files(targets: list[Path], cwd: str | None = None) -> list[SlopViolation]:
    extra_rules = load_worktree_guard_config(cwd=cwd)["extra_slop_rules"]
    all_violations: list[SlopViolation] = []
    valid_exts = set(CODE_SCAN_EXTS)
    for path in targets:
        if path.suffix not in valid_exts or path.name in SELF_SKIP_NAMES:
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise GuardAnalysisError(f"Failed to read {path}: {exc}") from exc
        rel_str = str(path)
        all_violations.extend(scan_text_for_slop(content, rel_str, extra_rules=extra_rules))
        if path.suffix == ".py":
            all_violations.extend(v for v in scan_ast_for_refactoring_slop(content, rel_str, changed_lines=set(), extra_rules=extra_rules) if v.category == "syntax_error")
    return all_violations


def _report_violations(all_violations: list[SlopViolation]) -> int:
    analysis_errors = [v for v in all_violations if v.category in ("syntax_error", "guard_analysis_error")]
    if analysis_errors:
        print(f"\n❌ Guard Analysis Error ({len(analysis_errors)}):", file=sys.stderr)
        for v in analysis_errors:
            print(f"  {v.file}:{v.line} -> [{v.category}] {v.message}", file=sys.stderr)
        return 2

    print(f"\n❌ AI Slop / Anti-Shortcutting Violations Detected ({len(all_violations)}):", file=sys.stderr)
    for v in all_violations:
        print(f"  {v.file}:{v.line} -> [{v.category}] {v.message}", file=sys.stderr)
        print(f"    Snippet: {v.snippet}", file=sys.stderr)
    return 1


FILE_SCAN_SCOPE_NOTE = (
    "note: file scan runs text rules and syntax checks only; use --staged-only, --diff-base or --commit-range "
    "for AST, topology and test-integrity checks"
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="AI Slop & Anti-Hacking Scanner")
    parser.add_argument("--staged-only", action="store_true", help="Scan git index against HEAD")
    parser.add_argument("--diff-base", default=None, help="Base commit ref for single diff scan")
    parser.add_argument("--head-ref", default="HEAD", help="Target commit ref for --diff-base")
    parser.add_argument("--commit-range", default=None, help="Commit range <base>..<head> for per-commit + aggregate scan")
    parser.add_argument("--test-fixtures", action="store_true", help="Run self-test against fixtures")
    parser.add_argument("files", nargs="*", help="Specific files or folders to scan")
    args = parser.parse_args(argv)

    if args.test_fixtures:
        return 0 if run_fixtures_self_test() else 1
    lock_rc = check_staged_lock() if args.staged_only else None
    if lock_rc is not None:
        return lock_rc

    try:
        if args.commit_range:
            all_violations = _evaluate_commit_range(args.commit_range)
        elif args.diff_base:
            base_sha = verify_commit_ref(args.diff_base)
            head_sha = verify_commit_ref(args.head_ref)
            all_violations = _evaluate_transition(base_sha, head_sha)
        elif args.staged_only:
            all_violations = _evaluate_transition("HEAD", None)
        else:
            print(FILE_SCAN_SCOPE_NOTE, file=sys.stderr)
            targets = _resolve_scan_targets(args)
            all_violations = _scan_worktree_files(targets)
    except GuardAnalysisError as exc:
        print(f"ERROR: [guard_analysis_error] {exc}", file=sys.stderr)
        return 2

    if all_violations:
        return _report_violations(all_violations)

    if args.staged_only or args.commit_range or args.diff_base:
        print("✅ Git snapshot clean of AI slop, AST regressions, shortcut escapes, and test tampering.")
    else:
        print("✅ Scanned files — zero slop violations detected.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
