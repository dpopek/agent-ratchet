#!/usr/bin/env python3
"""Stdlib-only AST analyzer (RULES_VERSION = "2.3.3") enforcing S1-S6, A4, C1, and C5."""

from __future__ import annotations

import ast
import warnings
from typing import Any, Mapping, Sequence

import agent_ratchet.ast_refactoring_delta as _delta
from agent_ratchet.ast_refactoring_delta import (
    DUMPING_GROUND_FILENAME_RE as DUMPING_GROUND_FILENAME_RE, FORBIDDEN_DOMAIN_CALL_TARGETS, FORBIDDEN_DOMAIN_IMPORT_MODULES,
    FORBIDDEN_DOMAIN_LAYER_SEGMENTS, FORBIDDEN_PATH_DISK_METHODS,
    BranchKind as BranchKind, ExitKind as ExitKind, FunctionVariantMetrics as FunctionVariantMetrics, ModuleAstSnapshot as ModuleAstSnapshot,
    ScopeKind as ScopeKind, _FlowState, _ScopeFrame, _build_param_key, _calls_target_with_varargs, _check_empty_subclass_rules,
    _check_passthrough_wrapper_rules, _iter_assigned_names, _names_outside_calls, check_staged_file_size_buffer as check_staged_file_size_buffer,
    collect_refactoring_slop_entries as collect_refactoring_slop_entries, compare_ast_snapshots as compare_ast_snapshots,
    compute_max_control_nesting_depth, count_effective_params, evaluate_loc_transition as evaluate_loc_transition,
    extract_changed_lines_map as extract_changed_lines_map, git_show_text as git_show_text, is_domain_file, is_query_function_name,
    is_safe_local_container_allocation, is_valid_deterministic_random_seed_call, register_snapshot_extractor
)
from agent_ratchet.ast_control_flow import ControlFlowVisitorMixin
from agent_ratchet.query_mutation_rules import query_call_mutation_message, query_target_mutation_message
from agent_ratchet.git_guard_io import (
    APP_CODE_PREFIXES as APP_CODE_PREFIXES, RULES_VERSION as RULES_VERSION, HARD_FILE_CEILING_LOC as HARD_FILE_CEILING_LOC,
    MAX_CONTROL_NESTING_DEPTH, MAX_FUNCTION_ARGS, MODIFIED_FILE_SOFT_CEILING_LOC as MODIFIED_FILE_SOFT_CEILING_LOC,
    GuardAnalysisError as GuardAnalysisError, SlopViolation, git_show_bytes as git_show_bytes, is_self_skipped, is_test_filename, parse_python, visit_bounded
)
__all__ = ["APP_CODE_PREFIXES", "BranchKind", "DUMPING_GROUND_FILENAME_RE", "ExitKind", "FunctionVariantMetrics", "GuardAnalysisError", "HARD_FILE_CEILING_LOC", "MODIFIED_FILE_SOFT_CEILING_LOC", "ModuleAstSnapshot", "RULES_VERSION", "ScopeKind", "SlopViolation", "check_staged_file_size_buffer", "collect_full_scan_violations", "collect_refactoring_slop_entries", "compare_ast_snapshots", "evaluate_loc_transition", "extract_ast_snapshot", "extract_changed_lines_map", "git_show_bytes", "git_show_text", "scan_ast_for_refactoring_slop"]



def __getattr__(name: str) -> object:
    if name == "GUARD_VERSION":
        warnings.warn("agent_ratchet.refactoring_guard.GUARD_VERSION is deprecated and removed in 4.0; use agent_ratchet.refactoring_guard.RULES_VERSION", DeprecationWarning, stacklevel=2)
        return RULES_VERSION
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


class _AstSnapshotBuilder(ControlFlowVisitorMixin):
    def __init__(self, filename: str, lines: list[str]) -> None:
        self.filename, self.lines = filename, lines
        self.is_test = is_test_filename(filename)
        self.is_domain = not self.is_test and is_domain_file(filename)
        self.frames: list[_ScopeFrame] = [_ScopeFrame(kind=ScopeKind.MODULE)]
        self.qualname_stack: list[str] = []
        self.branch_stack: list[BranchKind] = [BranchKind.TOP_LEVEL]
        self.context_stack: list[str] = []
        self.func_params_stack: list[set[str]] = []
        self.func_body_accum_stack: list[dict[str, int]] = []
        self._try_exc_accum_stack: list[list[_FlowState]] = []
        self._suppress_violation_recording = self._in_optional_import_try = self._seen_runtime_def_or_class = False
        self._defined_module_names: set[str] = set()
        self._variant_seq: dict[tuple[str, str], int] = {}
        self.runtime_variants: dict[str, list[FunctionVariantMetrics]] = {}
        self.overload_variants: dict[str, list[FunctionVariantMetrics]] = {}
        self.non_function_counts: dict[tuple[str, str], int] = {}
        self.non_function_lines: dict[tuple[str, str], int] = {}
        self.full_violations: list[SlopViolation] = []

    @property
    def current_frame(self) -> _ScopeFrame: return self.frames[-1]
    @property
    def current_scope(self) -> ScopeKind: return self.frames[-1].kind
    @property
    def current_branch(self) -> BranchKind: return self.branch_stack[-1]

    def _record_violation(self, lineno: int, category: str, message: str, count_in_owner: bool = True) -> None:
        if self._suppress_violation_recording:
            return
        snip = self.lines[lineno - 1].strip()[:100] if 1 <= lineno <= len(self.lines) else ""
        self.full_violations.append(SlopViolation(self.filename, lineno, category, message, snip))
        if not count_in_owner:
            return
        if self.func_body_accum_stack:
            acc = self.func_body_accum_stack[-1]
            acc[category] = acc.get(category, 0) + 1
        else:
            key = (".".join(self.qualname_stack) if self.qualname_stack else "<module>", category)
            self.non_function_counts[key] = self.non_function_counts.get(key, 0) + 1
            self.non_function_lines.setdefault(key, lineno)

    def _resolve_name(self, name: str) -> str:
        top_idx = len(self.frames) - 1
        has_func_above = False
        for idx in range(top_idx, -1, -1):
            frame = self.frames[idx]
            if idx < top_idx and frame.kind == ScopeKind.CLASS and has_func_above:
                continue
            if frame.kind == ScopeKind.FUNCTION:
                has_func_above = True
            if name in frame.bindings:
                val = frame.bindings[name]
                return "" if val == "SHADOWED" else val
            if frame.kind == ScopeKind.FUNCTION and name in frame.local_names:
                return ""
        return _delta._DEFAULT_SYMBOL_BINDINGS.get(name, "")

    def _resolve_expr_binding(self, expr: ast.AST) -> str:
        if isinstance(expr, ast.Name):
            return self._resolve_name(expr.id)
        if isinstance(expr, ast.Attribute):
            base_b = self._resolve_expr_binding(expr.value)
            if base_b.startswith("module:"):
                raw_mod = base_b.split(":", 1)[1]
                return _delta._TRACKED_IMPORT_TARGETS.get((raw_mod, expr.attr), f"{raw_mod}.{expr.attr}")
            return f"{base_b}.{expr.attr}" if base_b else ""
        return ""

    def _bind_symbol(self, local_name: str, target: str) -> None:
        if self.current_branch != BranchKind.TYPE_CHECKING:
            frame = self.current_frame
            frame.local_names.add(local_name)
            frame.protected_params.discard(local_name)
            frame.bindings[local_name] = target if target else "SHADOWED"

    def _shadow_target_names(self, target: ast.AST) -> None:
        for name in _iter_assigned_names(target):
            self._bind_symbol(name, "")

    def _register_module_runtime_symbol(self, name: str) -> None:
        if self.current_scope == ScopeKind.MODULE and self.current_branch != BranchKind.TYPE_CHECKING:
            self._seen_runtime_def_or_class = True
            self._defined_module_names.add(name)

    def visit_Module(self, node: ast.Module) -> None:
        self._visit_stmt_list(node.body)

    def _check_c5_target_mutation(self, tgt: ast.AST, is_plain_assign: bool) -> None:
        if self.is_test or self.current_branch == BranchKind.TYPE_CHECKING or self.current_scope != ScopeKind.FUNCTION or not self.current_frame.is_query:
            return
        frame = self.current_frame
        message = query_target_mutation_message(tgt, is_plain_assign, frame.protected_receivers, frame.protected_params)
        if message is not None:
            self._record_violation(getattr(tgt, "lineno", 1), "query_mutation_side_effect", message)

    def _apply_assignment_target(self, tgt: ast.AST, val: ast.AST | None) -> None:
        self._check_c5_target_mutation(tgt, is_plain_assign=True)
        frame = self.current_frame
        if isinstance(tgt, ast.Name):
            name = tgt.id
            if val is not None and isinstance(val, ast.Name) and val.id in frame.protected_params:
                frame.protected_params.add(name)
            elif val is not None and is_safe_local_container_allocation(val, self._resolve_expr_binding):
                frame.protected_params.discard(name)
            new_binding = "SHADOWED"
            if val is not None:
                if isinstance(val, ast.Name):
                    new_binding = self._resolve_name(val.id) or "SHADOWED"
                elif isinstance(val, ast.Call) and self._resolve_expr_binding(val.func) == "pathlib.Path":
                    new_binding = "instance:pathlib.Path"
            frame.local_names.add(name)
            frame.bindings[name] = new_binding
        elif isinstance(tgt, (ast.Tuple, ast.List)):
            if isinstance(val, (ast.Tuple, ast.List)) and len(tgt.elts) == len(val.elts) and not any(isinstance(e, ast.Starred) for e in tgt.elts):
                for t_elt, v_elt in zip(tgt.elts, val.elts):
                    self._apply_assignment_target(t_elt, v_elt)
            else:
                aliases_prot = val is not None and any(name in frame.protected_params for name in _names_outside_calls(val))
                for sub_name in _iter_assigned_names(tgt):
                    frame.local_names.add(sub_name)
                    frame.bindings[sub_name] = "SHADOWED"
                    if aliases_prot:
                        frame.protected_params.add(sub_name)
        else:
            self.visit(tgt)

    def _check_module_assign_rules(self, stmt: ast.Assign) -> None:
        if len(stmt.targets) != 1 or not isinstance(stmt.targets[0], ast.Name):
            return
        t_name = stmt.targets[0].id
        if not self.is_test and (t_name.startswith("_default_") or t_name.endswith(("_factory", "_registry"))):
            self._record_violation(stmt.lineno, "global_monkeypatch_state", f"Mutable module-level factory/registry '{t_name}' is forbidden; inject dependencies explicitly.")
        if isinstance(stmt.value, ast.Name):
            v_name = stmt.value.id
            is_alias = v_name in self._defined_module_names or (t_name.startswith("_") and t_name.lstrip("_") == v_name)
            if v_name not in _delta._BUILTIN_TYPE_NAMES and not t_name.isupper() and is_alias:
                self._record_violation(stmt.lineno, "symbol_alias_bloat", f"Symbol alias '{t_name} = {v_name}' is forbidden (Zero-S2). Update callers and remove old name.")

    def visit_Assign(self, node: ast.Assign) -> None:
        self.visit(node.value)
        if self.current_scope == ScopeKind.MODULE and self.current_branch != BranchKind.TYPE_CHECKING:
            self._check_module_assign_rules(node)
        for tgt in node.targets:
            self._apply_assignment_target(tgt, node.value)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self.visit(node.value)
            self._apply_assignment_target(node.target, node.value)
        elif isinstance(node.target, ast.Name) and self.current_scope == ScopeKind.FUNCTION:
            self.current_frame.local_names.add(node.target.id)
        else:
            self.visit(node.target)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self.visit(node.target)
        self.visit(node.value)
        self._check_c5_target_mutation(node.target, is_plain_assign=False)
        for name in _iter_assigned_names(node.target):
            self.current_frame.local_names.add(name)
            self.current_frame.bindings[name] = "SHADOWED"

    def visit_Delete(self, node: ast.Delete) -> None:
        for tgt in node.targets:
            self.visit(tgt)
            self._check_c5_target_mutation(tgt, is_plain_assign=False)
            self._shadow_target_names(tgt)

    def _visit_for_loop(self, node: ast.For | ast.AsyncFor) -> None:
        self.visit(node.iter)
        self._shadow_target_names(node.target)
        self._visit_stmt_list(node.body)
        if node.orelse:
            self._visit_stmt_list(node.orelse)

    visit_For = visit_AsyncFor = _visit_for_loop

    def visit_While(self, node: ast.While) -> None:
        self.visit(node.test)
        self._visit_stmt_list(node.body)
        if node.orelse:
            self._visit_stmt_list(node.orelse)

    def _visit_with_stmt(self, node: ast.With | ast.AsyncWith) -> None:
        for item in node.items:
            self.visit(item.context_expr)
            if item.optional_vars is not None:
                self._shadow_target_names(item.optional_vars)
        self._visit_stmt_list(node.body)

    visit_With = visit_AsyncWith = _visit_with_stmt

    def _visit_comprehension_node(self, node: ast.AST, generators: Sequence[ast.comprehension], *exprs: ast.AST) -> None:
        self.frames.append(_ScopeFrame(
            kind=ScopeKind.FUNCTION, protected_params=set(self.current_frame.protected_params),
            protected_receivers=set(self.current_frame.protected_receivers), is_query=self.current_frame.is_query,
        ))
        for gen in generators:
            self.visit(gen.iter)
            self._shadow_target_names(gen.target)
            for if_expr in gen.ifs:
                self.visit(if_expr)
        for ex in exprs:
            self.visit(ex)
        self.frames.pop()

    def _visit_elt_comp(self, node: ast.ListComp | ast.SetComp | ast.GeneratorExp) -> None:
        self._visit_comprehension_node(node, node.generators, node.elt)

    visit_ListComp = visit_SetComp = visit_GeneratorExp = _visit_elt_comp

    def visit_DictComp(self, node: ast.DictComp) -> None:
        self._visit_comprehension_node(node, node.generators, node.key, node.value)

    def _check_domain_import(self, lineno: int, mod_name: str, imported_name: str = "") -> None:
        if not self.is_domain or self.current_branch == BranchKind.TYPE_CHECKING:
            return
        candidates = [mod_name] + ([f"{mod_name}.{imported_name}" if mod_name else imported_name] if imported_name else [])
        for cand in candidates:
            if not cand:
                continue
            if any(cand == lib or cand.startswith(f"{lib}.") for lib in FORBIDDEN_DOMAIN_IMPORT_MODULES):
                self._record_violation(lineno, "domain_impurity", f"Domain module imports forbidden I/O library '{cand}' (Zero-A4).")
                return
            bad_layers = set(cand.split(".")) & FORBIDDEN_DOMAIN_LAYER_SEGMENTS
            if bad_layers:
                self._record_violation(lineno, "domain_impurity", f"Domain module imports outer layer '{sorted(bad_layers)[0]}' via '{cand}' (Zero-A4).")
                return

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            local = alias.asname or alias.name.split(".")[0]
            top_mod = alias.name.split(".")[0]
            if not alias.asname and top_mod in _delta._TRACKED_MODULE_PREFIXES:
                self._bind_symbol(local, f"module:{top_mod}")
            elif alias.asname and alias.name in _delta._TRACKED_MODULE_PREFIXES:
                self._bind_symbol(local, f"module:{alias.name}")
            else:
                self._bind_symbol(local, "")
            self._check_domain_import(node.lineno, alias.name)
        self._check_import_placement(node.lineno)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        mod = node.module or ""
        for alias in node.names:
            local = alias.asname or alias.name
            target = _delta._TRACKED_IMPORT_TARGETS.get((mod, alias.name), "") or (f"{mod}.{alias.name}" if mod in _delta._TRACKED_MODULE_PREFIXES else "")
            self._bind_symbol(local, target)
            self._check_domain_import(node.lineno, mod, alias.name)
        if self.current_branch == BranchKind.TYPE_CHECKING:
            return
        self._check_import_placement(node.lineno)
        if not self.is_test and mod.startswith("src"):
            for alias in node.names:
                if alias.name.startswith("_") and not alias.name.startswith("__"):
                    self._record_violation(node.lineno, "nested_or_late_import", f"Cross-module import of private symbol '{alias.name}' is forbidden (Zero-S6).")

    def _check_import_placement(self, lineno: int) -> None:
        if self.current_branch == BranchKind.TYPE_CHECKING:
            return
        if self.current_scope != ScopeKind.MODULE:
            self._record_violation(lineno, "nested_or_late_import", "Import inside function/method/class is forbidden (Zero-S6).")
        elif self._seen_runtime_def_or_class:
            self._record_violation(lineno, "nested_or_late_import", "Late module-level import after def/class (E402 circular-import evasion) is forbidden.")
        elif self.current_branch == BranchKind.RUNTIME_CONDITIONAL and not self._in_optional_import_try:
            self._record_violation(lineno, "nested_or_late_import", "Conditional runtime import at module level is forbidden (Zero-S6).")

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._register_module_runtime_symbol(node.name)
        self._bind_symbol(node.name, "")
        for expr in [*node.decorator_list, *node.bases]:
            self.visit(expr)
        if self.current_branch != BranchKind.TYPE_CHECKING and node.bases:
            _check_empty_subclass_rules(node, self._record_violation)
        self.qualname_stack.append(node.name)
        self.frames.append(_ScopeFrame(kind=ScopeKind.CLASS))
        self._visit_stmt_list(node.body)
        self.frames.pop()
        self.qualname_stack.pop()

    def _is_valid_wraps_closure(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef, parent_scope: ScopeKind, effective_params: int, enclosing_func_params: set[str]
    ) -> bool:
        if parent_scope != ScopeKind.FUNCTION or effective_params > 1:
            return False
        for dec in node.decorator_list:
            if isinstance(dec, ast.Call) and len(dec.args) == 1 and not dec.keywords and self._resolve_expr_binding(dec.func) == "functools.wraps":
                arg0 = dec.args[0]
                if isinstance(arg0, ast.Name) and arg0.id in enclosing_func_params and _calls_target_with_varargs(node, arg0.id):
                    return True
        return False

    def _visit_func(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        parent_scope = self.current_scope
        for expr in [*node.decorator_list, *node.args.defaults, *(d for d in node.args.kw_defaults if d is not None)]:
            self.visit(expr)
        resolved_decs = {self._resolve_expr_binding(d.func if isinstance(d, ast.Call) else d) for d in node.decorator_list} - {""}
        enclosing_params = self.func_params_stack[-1] if self.func_params_stack else set()
        eff_params, drop_receiver = count_effective_params(node, parent_scope, resolved_decs)
        valid_wraps = self._is_valid_wraps_closure(node, parent_scope, eff_params, enclosing_params)
        self._register_module_runtime_symbol(node.name)
        self._bind_symbol(node.name, "")
        if self.current_branch == BranchKind.TYPE_CHECKING:
            return

        param_key = _build_param_key(node.args, drop_receiver)
        has_unjustified_varargs = bool((node.args.vararg or node.args.kwarg) and node.name != "__init__" and not valid_wraps)
        is_overload = "typing.overload" in resolved_decs
        is_stub_allowed = is_overload or ("abc.abstractmethod" in resolved_decs)
        max_nesting_depth = 0 if is_overload else compute_max_control_nesting_depth(node.body, 0)
        qualname = ".".join(self.qualname_stack + [node.name])
        ctx_base = "/".join(self.context_stack) if self.context_stack else "def"
        seq = self._variant_seq.get((qualname, ctx_base), 0) if not self._suppress_violation_recording else 0
        if not self._suppress_violation_recording:
            self._variant_seq[(qualname, ctx_base)] = seq + 1
        variant_ctx = f"{ctx_base}#{seq}"

        if not self.is_test:
            if eff_params > MAX_FUNCTION_ARGS:
                self._record_violation(node.lineno, "excessive_parameter_list", f"Function '{qualname}' has {eff_params} parameters (max {MAX_FUNCTION_ARGS}). Pass a frozen @dataclass DTO.", count_in_owner=False)
            elif has_unjustified_varargs:
                self._record_violation(node.lineno, "excessive_parameter_list", f"Function '{qualname}' uses *args/**kwargs without valid @wraps closure. Use a @dataclass DTO.", count_in_owner=False)
            if max_nesting_depth > MAX_CONTROL_NESTING_DEPTH:
                self._record_violation(node.lineno, "excessive_nesting_depth", f"Function '{qualname}' has control nesting depth {max_nesting_depth} (max {MAX_CONTROL_NESTING_DEPTH}) (Zero-C1).", count_in_owner=False)

        pos_args = [a.arg for a in list(node.args.posonlyargs) + list(node.args.args)]
        kw_args = [a.arg for a in node.args.kwonlyargs]
        receivers = {pos_args[0]} if (drop_receiver and pos_args) else set()
        prot_params = set(pos_args[1:] if drop_receiver else pos_args) | set(kw_args)
        own_params = set(pos_args) | set(kw_args) | ({node.args.vararg.arg} if node.args.vararg else set()) | ({node.args.kwarg.arg} if node.args.kwarg else set())

        self.frames.append(_ScopeFrame(
            kind=ScopeKind.FUNCTION, bindings={p: "SHADOWED" for p in own_params}, local_names=set(own_params),
            protected_params=prot_params, protected_receivers=receivers, is_query=is_query_function_name(node.name),
        ))
        self.qualname_stack.append(node.name)
        self.func_params_stack.append(own_params)
        self.func_body_accum_stack.append({})
        if not self.is_test and not is_stub_allowed:
            _check_passthrough_wrapper_rules(node, drop_receiver, qualname, self._record_violation)
        if not is_overload:
            self._visit_stmt_list(node.body)
        body_acc, _, _, _ = self.func_body_accum_stack.pop(), self.func_params_stack.pop(), self.qualname_stack.pop(), self.frames.pop()
        if not self.is_test and not self._suppress_violation_recording:
            metrics = FunctionVariantMetrics(qualname, node.lineno, variant_ctx, eff_params, has_unjustified_varargs, max_nesting_depth, param_key, tuple(sorted(body_acc.items())), is_overload)
            (self.overload_variants if is_overload else self.runtime_variants).setdefault(qualname, []).append(metrics)

    visit_FunctionDef = visit_AsyncFunctionDef = _visit_func

    def visit_Global(self, node: ast.Global) -> None:
        if not self.is_test and self.current_branch != BranchKind.TYPE_CHECKING:
            self._record_violation(node.lineno, "global_monkeypatch_state", "Use of 'global' statement is forbidden (Zero-S3).")

    def visit_Name(self, node: ast.Name) -> None:
        if self.is_domain and self.current_branch != BranchKind.TYPE_CHECKING and isinstance(node.ctx, ast.Load) and self._resolve_name(node.id) == "os.environ":
            self._record_violation(node.lineno, "domain_impurity", f"Domain module accesses process environment via '{node.id}' (Zero-A4).")

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if not self.is_test and self.current_branch != BranchKind.TYPE_CHECKING:
            if node.attr == "__dict__":
                self._record_violation(node.lineno, "defensive_getattr_slop", "Direct access to '__dict__' is forbidden (Zero-S1).")
            elif node.attr in _delta._FORBIDDEN_FRAME_ATTRS:
                self._record_violation(node.lineno, "global_monkeypatch_state", f"Bytecode/frame introspection via '{node.attr}' is forbidden (Zero-S3).")
            elif self.is_domain and isinstance(node.ctx, ast.Load) and self._resolve_expr_binding(node) == "os.environ":
                self._record_violation(node.lineno, "domain_impurity", "Domain module accesses 'os.environ' (Zero-A4).")
        self.generic_visit(node)

    def _check_domain_call(self, node: ast.Call) -> None:
        callee = self._resolve_expr_binding(node.func)
        if callee in FORBIDDEN_DOMAIN_CALL_TARGETS:
            self._record_violation(node.lineno, "domain_impurity", f"Domain module calls impure function '{callee}()' (Zero-A4).")
        elif callee == "random.Random" and not is_valid_deterministic_random_seed_call(node, self._resolve_expr_binding):
            self._record_violation(node.lineno, "domain_impurity", "Domain module calls 'Random()' without a verified constant deterministic seed (Zero-A4).")
        elif isinstance(node.func, ast.Attribute) and node.func.attr in FORBIDDEN_PATH_DISK_METHODS:
            recv = node.func.value
            if self._resolve_expr_binding(recv) == "instance:pathlib.Path" or (isinstance(recv, ast.Call) and self._resolve_expr_binding(recv.func) == "pathlib.Path"):
                self._record_violation(node.lineno, "domain_impurity", f"Domain module performs filesystem I/O via 'Path.{node.func.attr}()' (Zero-A4).")

    def _check_c5_call_mutation(self, node: ast.Call) -> None:
        if self.current_scope != ScopeKind.FUNCTION or not self.current_frame.is_query:
            return
        frame = self.current_frame
        message = query_call_mutation_message(node, self._resolve_expr_binding(node.func), frame.protected_receivers, frame.protected_params)
        if message is not None:
            self._record_violation(node.lineno, "query_mutation_side_effect", message)

    def visit_Call(self, node: ast.Call) -> None:
        if not self.is_test and self.current_branch != BranchKind.TYPE_CHECKING:
            if isinstance(node.func, ast.Name):
                fn_id = node.func.id
                if fn_id == "getattr" and len(node.args) >= 3:
                    self._record_violation(node.lineno, "defensive_getattr_slop", "3-argument getattr(obj, attr, default) is forbidden (Zero-S1). Rely on static dataclass attributes.")
                elif fn_id in ("hasattr", "vars", "locals"):
                    self._record_violation(node.lineno, "defensive_getattr_slop" if fn_id != "locals" else "excessive_parameter_list", f"Call to '{fn_id}()' is forbidden in domain/application code.")
            if self.is_domain:
                self._check_domain_call(node)
            self._check_c5_call_mutation(node)
        self.generic_visit(node)


def extract_ast_snapshot(source: str, filename: str, extra_rules: Sequence[Mapping[str, Any]] = ()) -> ModuleAstSnapshot:
    if not filename.endswith(".py") or is_self_skipped(filename):
        return ModuleAstSnapshot(filename, None, 0, {}, {}, {}, {}, [])
    try:
        tree = parse_python(source, filename)
    except SyntaxError as exc:
        err_msg, lineno = f"SyntaxError: {exc.msg}", exc.lineno or 1
        return ModuleAstSnapshot(filename, err_msg, lineno, {}, {}, {}, {}, [SlopViolation(filename, lineno, "syntax_error", err_msg, "")])
    b = _AstSnapshotBuilder(filename, source.splitlines())
    visit_bounded(lambda: b.visit(tree), filename)
    return ModuleAstSnapshot(filename, None, 0, b.runtime_variants, b.overload_variants, b.non_function_counts, b.non_function_lines, b.full_violations)
register_snapshot_extractor(extract_ast_snapshot)

def collect_full_scan_violations(source: str, filename: str, extra_rules: Sequence[Mapping[str, Any]] = ()) -> list[SlopViolation]:
    return list(extract_ast_snapshot(source, filename, extra_rules=extra_rules).full_violations)

def scan_ast_for_refactoring_slop(content: str, filename: str, changed_lines: set[int] | None = None, extra_rules: Sequence[Mapping[str, Any]] = ()) -> list[SlopViolation]:
    if not filename.endswith(".py") or is_self_skipped(filename):
        return []
    full = collect_full_scan_violations(content, filename, extra_rules=extra_rules)
    return full if changed_lines is None else [v for v in full if v.line in changed_lines]
