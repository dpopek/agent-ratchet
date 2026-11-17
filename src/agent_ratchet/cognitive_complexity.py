#!/usr/bin/env python3
"""Stdlib-only cognitive complexity (SonarSource rules adapted to Python) for the Guard Core 2.3.0 file budget."""

from __future__ import annotations

import ast
from typing import Mapping, NamedTuple

from agent_ratchet.ast_safety import parse_python, visit_bounded

COGNITIVE_FUNCTION_CEILING: int = 15
COGNITIVE_MODULE_CEILING: int = 200

_TRY_NODES: tuple[type[ast.AST], ...] = (ast.Try,) + ((ast.TryStar,) if hasattr(ast, "TryStar") else ())
_LOOP_NODES: tuple[type[ast.AST], ...] = (ast.For, ast.AsyncFor, ast.While)
_DEF_NODES: tuple[type[ast.AST], ...] = (ast.FunctionDef, ast.AsyncFunctionDef)


class FunctionScore(NamedTuple):
    line: int
    score: int


def _expr_cost(expr: ast.AST | None, nesting: int) -> int:
    """Boolean operator sequences +1 each, ternaries +1 plus nesting, comprehensions +1 plus one per filter."""
    if expr is None:
        return 0
    cost = 0
    for node in ast.walk(expr):
        if isinstance(node, ast.BoolOp):
            cost += 1
        elif isinstance(node, ast.IfExp):
            cost += 1 + nesting
        elif isinstance(node, ast.comprehension):
            cost += 1 + len(node.ifs)
    return cost


def _body_cost(body: list[ast.stmt], nesting: int) -> int:
    return sum(_stmt_cost(stmt, nesting) for stmt in body)


def _if_cost(node: ast.If, nesting: int) -> int:
    cost = 1 + nesting + _expr_cost(node.test, nesting) + _body_cost(node.body, nesting + 1)
    orelse = node.orelse
    while len(orelse) == 1 and isinstance(orelse[0], ast.If):
        branch = orelse[0]
        cost += 1 + _expr_cost(branch.test, nesting) + _body_cost(branch.body, nesting + 1)
        orelse = branch.orelse
    if orelse:
        cost += 1 + _body_cost(orelse, nesting + 1)
    return cost


def _loop_cost(node: ast.For | ast.AsyncFor | ast.While, nesting: int) -> int:
    header = node.test if isinstance(node, ast.While) else node.iter
    cost = 1 + nesting + _expr_cost(header, nesting) + _body_cost(node.body, nesting + 1)
    return cost + (1 + _body_cost(node.orelse, nesting + 1) if node.orelse else 0)


def _try_cost(node: ast.Try, nesting: int) -> int:
    cost = _body_cost(node.body, nesting) + _body_cost(node.orelse, nesting) + _body_cost(node.finalbody, nesting)
    return cost + sum(1 + nesting + _body_cost(handler.body, nesting + 1) for handler in node.handlers)


def _stmt_cost(stmt: ast.stmt, nesting: int) -> int:
    if isinstance(stmt, _DEF_NODES):
        return _body_cost(stmt.body, nesting + 1)
    if isinstance(stmt, ast.ClassDef):
        return _body_cost(stmt.body, nesting)
    if isinstance(stmt, ast.If):
        return _if_cost(stmt, nesting)
    if isinstance(stmt, _LOOP_NODES):
        return _loop_cost(stmt, nesting)
    if isinstance(stmt, _TRY_NODES):
        return _try_cost(stmt, nesting)
    if isinstance(stmt, ast.Match):
        return 1 + nesting + sum(_body_cost(case.body, nesting + 1) + _expr_cost(case.guard, nesting) for case in stmt.cases)
    if isinstance(stmt, (ast.With, ast.AsyncWith)):
        return _body_cost(stmt.body, nesting) + sum(_expr_cost(item.context_expr, nesting) for item in stmt.items)
    return sum(_expr_cost(child, nesting) for child in ast.iter_child_nodes(stmt) if isinstance(child, ast.expr))


def _collect_scores(body: list[ast.stmt], prefix: str, out: dict[str, FunctionScore]) -> None:
    for stmt in body:
        if isinstance(stmt, _DEF_NODES):
            qualname = f"{prefix}{stmt.name}"
            score = FunctionScore(stmt.lineno, _body_cost(stmt.body, 0))
            if qualname not in out or score.score > out[qualname].score:
                out[qualname] = score
        elif isinstance(stmt, ast.ClassDef):
            _collect_scores(stmt.body, f"{prefix}{stmt.name}.", out)


def function_cognitive_scores(source: str, filename: str = "<source>") -> dict[str, FunctionScore]:
    """Map each top-level function and method qualname to its score; nested defs fold into their parent. Raises SyntaxError, or GuardAnalysisError when the AST is too deep."""
    scores: dict[str, FunctionScore] = {}
    tree = parse_python(source, filename)
    visit_bounded(lambda: _collect_scores(tree.body, "", scores), filename)
    return scores


def safe_function_cognitive_scores(source: str | None, filename: str = "<source>") -> dict[str, FunctionScore] | None:
    """Scores, or None when the source is absent or has a syntax error (reported by the AST scanner); too-deep ASTs raise GuardAnalysisError."""
    if source is None:
        return None
    try:
        return function_cognitive_scores(source, filename)
    except (SyntaxError, ValueError):
        return None


def module_cognitive_total(scores: Mapping[str, FunctionScore] | None) -> int:
    return sum(s.score for s in scores.values()) if scores else 0


def worsened_complex_functions(base: Mapping[str, FunctionScore] | None, target: Mapping[str, FunctionScore]) -> list[tuple[str, int, int, int]]:
    """(qualname, line, base_score, target_score) for functions above the ceiling that are new or grew versus base."""
    base_map = base or {}
    out: list[tuple[str, int, int, int]] = []
    for qualname, cur in sorted(target.items(), key=lambda item: item[1].line):
        prev = base_map[qualname].score if qualname in base_map else 0
        if cur.score > COGNITIVE_FUNCTION_CEILING and cur.score > prev:
            out.append((qualname, cur.line, prev, cur.score))
    return out


class BudgetFinding(NamedTuple):
    line: int
    message: str
    detail: str


def evaluate_cognitive_budget(rel_path: str, base_text: str | None, target_text: str, ceiling_override: int | None = None) -> tuple[list[BudgetFinding], int]:
    """Function ceiling for new or grown functions plus a module ratchet; returns findings and the ceiling to carry forward."""
    target_scores, base_scores = safe_function_cognitive_scores(target_text, rel_path), safe_function_cognitive_scores(base_text, rel_path)
    t_total, b_total = module_cognitive_total(target_scores), module_cognitive_total(base_scores)
    allowed = ceiling_override if ceiling_override is not None else max(COGNITIVE_MODULE_CEILING, b_total)
    if target_scores is None:
        return [], allowed
    findings = [
        BudgetFinding(line, f"Function '{qualname}' cognitive complexity {cur} exceeds {COGNITIVE_FUNCTION_CEILING} and grew from {prev}. Extract cohesive steps.", f"{qualname}: {prev} -> {cur}")
        for qualname, line, prev, cur in worsened_complex_functions(base_scores, target_scores)
    ]
    if t_total > allowed:
        msg = f"Module '{rel_path}' cognitive complexity grew to {t_total}, exceeding allowed ceiling {allowed} (Zero-S6). Split along cohesive responsibilities."
        return [*findings, BudgetFinding(1, msg, f"{b_total} -> {t_total} cognitive")], allowed
    return findings, max(COGNITIVE_MODULE_CEILING, t_total)
