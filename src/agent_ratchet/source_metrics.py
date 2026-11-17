#!/usr/bin/env python3
"""Stdlib-only source metrics for Guard Core 2.3.3: JS lexing, effective SLOC and test assertion counting."""

from __future__ import annotations

import ast
import re

from agent_ratchet.ast_safety import parse_python, visit_bounded

JS_LIKE_EXTS: tuple[str, ...] = (".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs")


def _python_docstring_lines(rel_path: str, content: str) -> set[int]:
    try:
        tree = parse_python(content, rel_path)
    except SyntaxError:
        return set()
    doc_lines: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) or not node.body:
            continue
        first = node.body[0]
        if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and isinstance(first.value.value, str):
            start = first.lineno
            end = getattr(first, "end_lineno", start) or start
            if not isinstance(node, ast.Module) and start == node.lineno:
                start = node.lineno + 1
            doc_lines.update(range(start, end + 1))
    return doc_lines


def _consume_quoted_js(content: str, start: int) -> int:
    quote, idx, n = content[start], start + 1, len(content)
    while idx < n:
        ch = content[idx]
        idx += 2 if ch == "\\" else 1
        if ch == quote:
            break
    return min(idx, n)


def strip_js_comments(content: str) -> str:
    out: list[str] = []
    i, n = 0, len(content)
    while i < n:
        two = content[i : i + 2]
        if content[i] in ("'", '"', "`"):
            end = _consume_quoted_js(content, i)
            out.append(content[i:end])
            i = end
        elif two == "//":
            nl_pos = content.find("\n", i + 2)
            i = n if nl_pos == -1 else nl_pos
        elif two == "/*":
            end = content.find("*/", i + 2)
            seg_end = n if end == -1 else end + 2
            out.append("\n" * content.count("\n", i, seg_end) or " ")
            i = seg_end
        else:
            out.append(content[i])
            i += 1
    return "".join(out)


def count_effective_sloc(rel_path: str, content: str) -> int:
    if rel_path.endswith(".py"):
        doc_lines = _python_docstring_lines(rel_path, content)
        return sum(1 for idx, ln in enumerate(content.splitlines(), 1) if idx not in doc_lines and (s := ln.strip()) and not s.startswith("#"))
    if rel_path.endswith(JS_LIKE_EXTS):
        return sum(1 for ln in strip_js_comments(content).splitlines() if ln.strip())
    return sum(1 for ln in content.splitlines() if ln.strip())


def _node_assertion_count(node: ast.AST) -> int:
    if isinstance(node, ast.Assert):
        return 1
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute) and (node.func.attr.startswith("assert") or node.func.attr in ("raises", "warns", "fail")):
            return 1
        if isinstance(node.func, ast.Name) and node.func.id.startswith("assert"):
            return 1
    return 0


def _parametrize_multiplier(func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> int:
    mult = 1
    for dec in func_node.decorator_list:
        if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute) and dec.func.attr == "parametrize" and len(dec.args) >= 2 and isinstance(dec.args[1], (ast.List, ast.Tuple, ast.Set)):
            mult *= max(1, len(dec.args[1].elts))
    return mult


def _count_ast_assertions(node: ast.AST, multiplier: int = 1) -> int:
    total = _node_assertion_count(node) * multiplier
    for child in ast.iter_child_nodes(node):
        sub_m = multiplier * _parametrize_multiplier(child) if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) else multiplier
        total += _count_ast_assertions(child, sub_m)
    return total


def _find_balanced_span(text: str, open_pos: int, open_ch: str, close_ch: str) -> int:
    depth, idx, n = 0, open_pos, len(text)
    while idx < n:
        ch = text[idx]
        if ch in ("'", '"', "`"):
            idx = _consume_quoted_js(text, idx)
            continue
        if ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
            if depth == 0:
                return idx
        idx += 1
    return -1


def _count_js_top_level_items(arr_inner: str) -> int:
    s = arr_inner.strip()
    if not s:
        return 0
    depth, idx, n, commas, last_comma_pos = 0, 0, len(s), 0, -1
    while idx < n:
        ch = s[idx]
        if ch in ("'", '"', "`"):
            idx = _consume_quoted_js(s, idx)
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth = max(0, depth - 1)
        elif ch == "," and depth == 0:
            commas += 1
            last_comma_pos = idx
        idx += 1
    trailing = last_comma_pos != -1 and not s[last_comma_pos + 1 :].strip()
    return commas if trailing else commas + 1


def _count_js_assertions(content: str) -> int:
    no_comments = strip_js_comments(content)
    assert_re = re.compile(r"\b(?:expect|assert)\s*(?:\(|\.)")
    total = len(assert_re.findall(no_comments))
    for match in re.finditer(r"\b(?:it|test|describe)\.each\s*\(\s*\[", no_comments):
        arr_open = match.end() - 1
        arr_close = _find_balanced_span(no_comments, arr_open, "[", "]")
        if arr_close == -1:
            continue
        k = _count_js_top_level_items(no_comments[arr_open + 1 : arr_close])
        brace_open = no_comments.find("{", arr_close, arr_close + 300) if k > 1 else -1
        brace_close = _find_balanced_span(no_comments, brace_open, "{", "}") if brace_open != -1 else -1
        if brace_close != -1:
            total += (k - 1) * len(assert_re.findall(no_comments[brace_open + 1 : brace_close]))
    return total
