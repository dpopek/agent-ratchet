#!/usr/bin/env python3
"""Flow-sensitive statement visiting for Guard Core 2.3.3: statement lists, try/except/finally, if and match joins."""

from __future__ import annotations

import ast

import guard_core.ast_refactoring_delta as _delta
from guard_core.ast_refactoring_delta import (
    BranchKind, ExitKind, ScopeKind, _FlowState, _check_try_statement_rules, _is_top_level_optional_import_try,
    _is_version_or_platform_guard, _join_flow_states, _restore_flow_state, _snapshot_flow_state,
)


class ControlFlowVisitorMixin(ast.NodeVisitor):
    """Joins per-exit flow states across branches; the host visitor supplies frames, bindings and violation recording."""

    branch_stack: list[BranchKind]
    context_stack: list[str]
    is_test: bool
    _try_exc_accum_stack: list[list[_FlowState]]
    _suppress_violation_recording: bool
    _in_optional_import_try: bool
    _seen_runtime_def_or_class: bool

    def _merge_sub_outcomes(
        self, sub_out: dict[ExitKind, _FlowState], outcomes: dict[ExitKind, list[_FlowState]], reachable_normal: bool
    ) -> bool:
        for k, st in sub_out.items():
            if k != ExitKind.NORMAL and reachable_normal:
                outcomes.setdefault(k, []).append(st)
        if ExitKind.NORMAL in sub_out and reachable_normal:
            _restore_flow_state(self.current_frame, sub_out[ExitKind.NORMAL])
            return True
        return False

    def _visit_stmt_list(self, stmts: list[ast.stmt], ctx_prefix: str = "") -> dict[ExitKind, _FlowState]:
        frame = self.current_frame
        outcomes: dict[ExitKind, list[_FlowState]] = {}
        reachable_normal = True
        if_ord = 0
        for idx, stmt in enumerate(stmts):
            if isinstance(stmt, _delta._TRY_NODE_TYPES):
                if not self.is_test and self.current_branch != BranchKind.TYPE_CHECKING and isinstance(stmt, ast.Try):
                    _check_try_statement_rules(stmt, stmts[idx + 1 :], self._record_violation)
                prev_opt = self._in_optional_import_try
                if self.current_scope == ScopeKind.MODULE and self.current_branch == BranchKind.TOP_LEVEL and not self._seen_runtime_def_or_class and _is_top_level_optional_import_try(stmt):
                    self._in_optional_import_try = True
                reachable_normal = self._merge_sub_outcomes(self._visit_try_children(stmt), outcomes, reachable_normal)
                self._in_optional_import_try = prev_opt
            elif isinstance(stmt, ast.If):
                reachable_normal = self._merge_sub_outcomes(self._visit_if_with_index(stmt, f"{ctx_prefix}if@{if_ord}"), outcomes, reachable_normal)
                if_ord += 1
            elif _delta._MATCH_NODE_TYPES and isinstance(stmt, _delta._MATCH_NODE_TYPES):
                reachable_normal = self._merge_sub_outcomes(self._visit_match_stmt(stmt), outcomes, reachable_normal)
            else:
                self.visit(stmt)
                if reachable_normal and isinstance(stmt, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
                    st_now = _snapshot_flow_state(frame)
                    if isinstance(stmt, ast.Return):
                        outcomes.setdefault(ExitKind.RETURN, []).append(st_now)
                    elif isinstance(stmt, ast.Raise):
                        outcomes.setdefault(ExitKind.RAISE, []).append(st_now)
                        if self._try_exc_accum_stack:
                            self._try_exc_accum_stack[-1].append(st_now)
                    elif isinstance(stmt, ast.Break):
                        outcomes.setdefault(ExitKind.BREAK, []).append(st_now)
                    else:
                        outcomes.setdefault(ExitKind.CONTINUE, []).append(st_now)
                    reachable_normal = False
            if self._try_exc_accum_stack and reachable_normal:
                self._try_exc_accum_stack[-1].append(_snapshot_flow_state(frame))
        if reachable_normal:
            outcomes.setdefault(ExitKind.NORMAL, []).append(_snapshot_flow_state(frame))
        return {k: _join_flow_states(v) for k, v in outcomes.items() if v}

    def _compose_try_finalbody(
        self,
        final_stmts: list[ast.stmt],
        pre_finally: dict[ExitKind, _FlowState],
        s_exc_accum: _FlowState,
    ) -> dict[ExitKind, _FlowState]:
        frame = self.current_frame
        _restore_flow_state(frame, _join_flow_states(list(pre_finally.values()) + [s_exc_accum]))
        fin_out = self._visit_stmt_list(final_stmts)
        if ExitKind.NORMAL not in fin_out:
            return fin_out
        result_buckets: dict[ExitKind, list[_FlowState]] = {k: [v] for k, v in pre_finally.items() if k != ExitKind.NORMAL}
        for k, v in fin_out.items():
            if k != ExitKind.NORMAL:
                result_buckets.setdefault(k, []).append(v)
        if ExitKind.NORMAL in pre_finally:
            prev_sup = self._suppress_violation_recording
            self._suppress_violation_recording = True
            _restore_flow_state(frame, pre_finally[ExitKind.NORMAL])
            fin_norm_out = self._visit_stmt_list(final_stmts)
            self._suppress_violation_recording = prev_sup
            if ExitKind.NORMAL in fin_norm_out:
                result_buckets.setdefault(ExitKind.NORMAL, []).append(fin_norm_out[ExitKind.NORMAL])
        return {k: _join_flow_states(v) for k, v in result_buckets.items() if v}

    def _visit_try_children(self, node: ast.AST) -> dict[ExitKind, _FlowState]:
        frame = self.current_frame
        s_pre = _snapshot_flow_state(frame)
        self.branch_stack.append(BranchKind.TYPE_CHECKING if self.current_branch == BranchKind.TYPE_CHECKING else BranchKind.RUNTIME_CONDITIONAL)
        self._try_exc_accum_stack.append([s_pre])
        body_out = self._visit_stmt_list(list(getattr(node, "body", ())))
        exc_states = self._try_exc_accum_stack.pop()
        if ExitKind.RAISE in body_out:
            exc_states.append(body_out[ExitKind.RAISE])
        s_exc_accum = _join_flow_states(exc_states)

        orelse_stmts = list(getattr(node, "orelse", ()))
        merged_buckets: dict[ExitKind, list[_FlowState]] = {k: [v] for k, v in body_out.items() if k != ExitKind.NORMAL}
        if orelse_stmts:
            _restore_flow_state(frame, body_out.get(ExitKind.NORMAL, s_pre))
            orelse_out = self._visit_stmt_list(orelse_stmts)
            if ExitKind.NORMAL in body_out:
                for k, v in orelse_out.items():
                    merged_buckets.setdefault(k, []).append(v)
        elif ExitKind.NORMAL in body_out:
            merged_buckets.setdefault(ExitKind.NORMAL, []).append(body_out[ExitKind.NORMAL])

        is_trystar = node.__class__.__name__ == "TryStar"
        running_trystar_in = s_exc_accum
        for handler in getattr(node, "handlers", ()):
            _restore_flow_state(frame, running_trystar_in if is_trystar else s_exc_accum)
            if handler.name:
                self._bind_symbol(handler.name, "")
            h_out = self._visit_stmt_list(handler.body)
            for k, v in h_out.items():
                merged_buckets.setdefault(k, []).append(v)
            if is_trystar and ExitKind.NORMAL in h_out:
                running_trystar_in = _join_flow_states([running_trystar_in, h_out[ExitKind.NORMAL]])

        pre_finally = {k: _join_flow_states(v) for k, v in merged_buckets.items() if v}
        final_stmts = list(getattr(node, "finalbody", ()))
        final_map = self._compose_try_finalbody(final_stmts, pre_finally, s_exc_accum) if final_stmts else pre_finally
        self.branch_stack.pop()
        if ExitKind.NORMAL in final_map:
            _restore_flow_state(frame, final_map[ExitKind.NORMAL])
        return final_map

    def visit_Try(self, node: ast.Try) -> None:
        self._visit_try_children(node)

    def _visit_match_stmt(self, node: ast.AST) -> dict[ExitKind, _FlowState]:
        self.visit(getattr(node, "subject"))
        frame = self.current_frame
        s_pre = _snapshot_flow_state(frame)
        buckets: dict[ExitKind, list[_FlowState]] = {}
        has_irrefutable = False
        for case in getattr(node, "cases", ()):
            _restore_flow_state(frame, s_pre)
            pat = getattr(case, "pattern", None)
            if pat is not None and pat.__class__.__name__ == "MatchAs" and getattr(pat, "pattern", None) is None:
                if getattr(case, "guard", None) is None:
                    has_irrefutable = True
                if isinstance(getattr(pat, "name", None), str):
                    self._bind_symbol(pat.name, "")
            if getattr(case, "guard", None) is not None:
                self.visit(case.guard)
            for k, v in self._visit_stmt_list(case.body).items():
                buckets.setdefault(k, []).append(v)
        if not has_irrefutable:
            buckets.setdefault(ExitKind.NORMAL, []).append(s_pre)
        out = {k: _join_flow_states(v) for k, v in buckets.items() if v}
        if ExitKind.NORMAL in out:
            _restore_flow_state(frame, out[ExitKind.NORMAL])
        return out

    def _is_type_checking_condition(self, test: ast.AST) -> tuple[bool, bool]:
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not) and self._resolve_expr_binding(test.operand) == "typing.TYPE_CHECKING":
            return (False, True)
        return (True, False) if self._resolve_expr_binding(test) == "typing.TYPE_CHECKING" else (False, False)

    def _visit_if_branch(self, stmts: list[ast.stmt], is_tc: bool, ctx: str, s_pre: _FlowState) -> dict[ExitKind, _FlowState]:
        self.branch_stack.append(BranchKind.TYPE_CHECKING if is_tc else BranchKind.RUNTIME_CONDITIONAL)
        self.context_stack.append(ctx)
        _restore_flow_state(self.current_frame, s_pre)
        out = self._visit_stmt_list(stmts, f"{ctx}.")
        self.context_stack.pop()
        self.branch_stack.pop()
        return out

    def _visit_if_with_index(self, node: ast.If, tag: str) -> dict[ExitKind, _FlowState]:
        self.visit(node.test)
        frame = self.current_frame
        s_pre = _snapshot_flow_state(frame)
        if self.current_branch == BranchKind.TYPE_CHECKING:
            self._visit_if_branch(node.body, True, f"{tag}.body", s_pre)
            if node.orelse:
                self._visit_if_branch(node.orelse, True, f"{tag}.orelse", s_pre)
            return {ExitKind.NORMAL: s_pre}

        body_is_tc, orelse_is_tc = self._is_type_checking_condition(node.test)
        prev_opt = self._in_optional_import_try
        if self.current_scope == ScopeKind.MODULE and not self._seen_runtime_def_or_class and _is_version_or_platform_guard(node.test):
            self._in_optional_import_try = True

        is_neg = isinstance(node.test, ast.UnaryOp) and isinstance(node.test.op, ast.Not) and bool(node.orelse) and not body_is_tc and not orelse_is_tc
        body_ctx, else_ctx = (f"{tag}.orelse", f"{tag}.body") if is_neg else (f"{tag}.body", f"{tag}.orelse")
        body_out = self._visit_if_branch(node.body, body_is_tc, body_ctx, s_pre)
        else_out = self._visit_if_branch(node.orelse, orelse_is_tc, else_ctx, s_pre) if node.orelse else {ExitKind.NORMAL: s_pre}
        self._in_optional_import_try = prev_opt

        if body_is_tc or orelse_is_tc:
            chosen = else_out if body_is_tc else body_out
            if ExitKind.NORMAL in chosen:
                _restore_flow_state(frame, chosen[ExitKind.NORMAL])
            return chosen

        buckets: dict[ExitKind, list[_FlowState]] = {}
        for k, v in body_out.items():
            buckets.setdefault(k, []).append(v)
        for k, v in else_out.items():
            buckets.setdefault(k, []).append(v)
        joined = {k: _join_flow_states(v) for k, v in buckets.items() if v}
        if ExitKind.NORMAL in joined:
            _restore_flow_state(frame, joined[ExitKind.NORMAL])
        return joined

    def visit_If(self, node: ast.If) -> None:
        self._visit_if_with_index(node, "if@0")
