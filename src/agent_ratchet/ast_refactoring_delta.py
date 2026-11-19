#!/usr/bin/env python3
"""Variant pairing, AST snapshot delta comparison, C1 nesting, and A4/C5 helpers for Guard Core 2.3.3."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from enum import Enum
from pathlib import PurePosixPath
from typing import Any, Callable, Sequence

from agent_ratchet.git_guard_io import (
    APP_CODE_PREFIXES,
    DUMPING_GROUND_FILENAME_RE,
    MAX_CONTROL_NESTING_DEPTH,
    MAX_FUNCTION_ARGS,
    GuardAnalysisError,
    SlopViolation,
    check_staged_file_size_buffer,
    evaluate_loc_transition,
    extract_changed_lines_map,
    git_cat_bytes,
    git_show_text,
    NO_FIXTURES,
    is_self_skipped,
)


class ScopeKind(str, Enum):
    MODULE = "module"
    CLASS = "class"
    FUNCTION = "function"


class BranchKind(str, Enum):
    TOP_LEVEL = "top_level"
    RUNTIME_CONDITIONAL = "runtime_conditional"
    TYPE_CHECKING = "type_checking"


class ExitKind(str, Enum):
    NORMAL = "normal"
    RETURN = "return"
    RAISE = "raise"
    BREAK = "break"
    CONTINUE = "continue"


@dataclass(frozen=True)
class FunctionVariantMetrics:
    qualname: str
    lineno: int
    variant_context: str
    effective_params: int
    has_unjustified_varargs: bool
    max_nesting_depth: int
    param_key: tuple[tuple[str, str], ...]
    body_counts: tuple[tuple[str, int], ...]
    is_overload: bool = False

    @property
    def unchanged_profile_key(self) -> tuple[Any, ...]:
        return (self.effective_params, self.has_unjustified_varargs, self.max_nesting_depth, self.param_key, self.body_counts)

    def body_count_map(self) -> dict[str, int]:
        return dict(self.body_counts)


@dataclass(frozen=True)
class ModuleAstSnapshot:
    filename: str
    parse_error: str | None
    parse_lineno: int
    runtime_variants: dict[str, list[FunctionVariantMetrics]]
    overload_variants: dict[str, list[FunctionVariantMetrics]]
    non_function_counts: dict[tuple[str, str], int]
    non_function_lines: dict[tuple[str, str], int]
    full_violations: list[SlopViolation]


_FlowState = tuple[dict[str, str], set[str]]


@dataclass
class _ScopeFrame:
    kind: ScopeKind
    bindings: dict[str, str] = field(default_factory=dict)
    local_names: set[str] = field(default_factory=set)
    protected_params: set[str] = field(default_factory=set)
    protected_receivers: set[str] = field(default_factory=set)
    is_query: bool = False


def _snapshot_flow_state(frame: _ScopeFrame) -> _FlowState:
    return (dict(frame.bindings), set(frame.protected_params))


def _restore_flow_state(frame: _ScopeFrame, state: _FlowState) -> None:
    frame.bindings, frame.protected_params = dict(state[0]), set(state[1])


def _join_flow_states(states: Sequence[_FlowState]) -> _FlowState:
    if not states:
        return ({}, set())
    joined_prot: set[str] = set()
    all_keys: set[str] = set()
    for b_map, prot in states:
        joined_prot.update(prot)
        all_keys.update(b_map)
    joined_bindings: dict[str, str] = {}
    for key in all_keys:
        vals = [b_map[key] for b_map, _ in states if key in b_map]
        distinct = set(vals)
        joined_bindings[key] = "SHADOWED" if ("SHADOWED" in distinct or len(distinct) != 1) else next(iter(distinct))
    return (joined_bindings, joined_prot)


_TRY_NODE_TYPES: tuple[type[ast.AST], ...] = (ast.Try, ast.TryStar) if hasattr(ast, "TryStar") else (ast.Try,)
_MATCH_NODE_TYPES: tuple[type[ast.AST], ...] = (ast.Match,) if hasattr(ast, "Match") else ()

_QUERY_PREFIXES: tuple[str, ...] = (
    "is_", "has_", "can_", "should_", "get_", "find_", "lookup_", "search_",
    "compute_", "calculate_", "estimate_", "count_", "check_", "validate_", "verify_",
)
_QUERY_COMMAND_EXEMPT_TOKENS: tuple[str, ...] = (
    "_or_create", "_or_init", "_or_set", "_or_update", "_or_pop", "_or_default", "_or_populate",
    "_or_load", "_or_build", "_or_compute", "_or_fetch",
    "_and_set", "_and_update", "_and_pop", "_and_delete", "_and_clear", "_and_reset",
)
_SAFE_CONTAINER_CALL_BINDINGS: frozenset[str] = frozenset({
    "builtins.list", "builtins.dict", "builtins.set", "builtins.tuple", "builtins.frozenset", "builtins.sorted",
})
FORBIDDEN_DOMAIN_IMPORT_MODULES: frozenset[str] = frozenset({
    "requests", "httpx", "aiohttp", "urllib.request", "socket", "subprocess", "sqlite3", "psycopg",
    "psycopg2", "asyncpg", "sqlalchemy", "pymongo", "redis", "celery", "fastapi", "starlette", "flask", "django",
})
FORBIDDEN_DOMAIN_LAYER_SEGMENTS: frozenset[str] = frozenset({
    "infrastructure", "adapters", "api", "presentation", "ui", "cli", "views", "controllers",
})
FORBIDDEN_DOMAIN_CALL_TARGETS: frozenset[str] = frozenset({
    "datetime.datetime.now", "datetime.datetime.utcnow", "datetime.date.today",
    "time.time", "time.time_ns", "time.monotonic", "time.monotonic_ns", "time.perf_counter", "time.sleep",
    "random.random", "random.randint", "random.randrange", "random.choice", "random.choices",
    "random.sample", "random.shuffle", "random.uniform", "random.gauss", "random.normalvariate",
    "random.expovariate", "random.getrandbits", "random.randbytes", "random.seed", "random.SystemRandom",
    "secrets.choice", "secrets.randbelow", "secrets.randbits", "secrets.token_bytes",
    "secrets.token_hex", "secrets.token_urlsafe", "uuid.uuid1", "uuid.uuid4",
    "os.getenv", "os.putenv", "os.unsetenv", "os.system", "os.popen", "os.listdir", "os.scandir",
    "os.walk", "os.remove", "os.unlink", "os.makedirs", "os.mkdir", "os.rmdir", "os.rename", "os.replace",
    "builtins.open",
})
FORBIDDEN_PATH_DISK_METHODS: frozenset[str] = frozenset({
    "open", "read_text", "write_text", "read_bytes", "write_bytes", "mkdir", "unlink", "rmdir", "rename",
    "replace", "touch", "chmod", "iterdir", "glob", "rglob", "exists", "is_file", "is_dir", "is_symlink",
    "stat", "lstat", "resolve",
})
MUTATING_COLLECTION_METHODS: frozenset[str] = frozenset({
    "append", "extend", "insert", "pop", "remove", "clear", "sort", "reverse", "setdefault", "update", "add", "discard",
})


def is_domain_file(filename: str) -> bool:
    norm = filename.replace("\\", "/").lstrip("./")
    return norm.startswith(APP_CODE_PREFIXES) and "domain" in PurePosixPath(norm).parts[:-1]


def is_query_function_name(name: str) -> bool:
    stripped = name.lstrip("_")
    return stripped.startswith(_QUERY_PREFIXES) and not any(tok in stripped for tok in _QUERY_COMMAND_EXEMPT_TOKENS)


def is_safe_local_container_allocation(expr: ast.AST, resolve_binding_fn: Callable[[ast.AST], str]) -> bool:
    if isinstance(expr, (ast.List, ast.Dict, ast.Set, ast.Tuple, ast.ListComp, ast.DictComp, ast.SetComp)):
        return True
    return isinstance(expr, ast.Call) and resolve_binding_fn(expr.func) in _SAFE_CONTAINER_CALL_BINDINGS


def is_valid_deterministic_random_seed_call(node: ast.Call, resolve_binding_fn: Callable[[ast.AST], str]) -> bool:
    if len(node.args) == 1 and len(node.keywords) == 0:
        seed_expr = node.args[0]
        if isinstance(seed_expr, ast.Starred):
            return False
    elif len(node.args) == 0 and len(node.keywords) == 1 and node.keywords[0].arg == "x":
        seed_expr = node.keywords[0].value
    else:
        return False
    if isinstance(seed_expr, ast.Constant):
        return type(seed_expr.value) in (int, float, str, bytes, bool)
    if isinstance(seed_expr, ast.UnaryOp) and isinstance(seed_expr.op, (ast.UAdd, ast.USub)) and isinstance(seed_expr.operand, ast.Constant):
        return type(seed_expr.operand.value) in (int, float)
    return (
        isinstance(seed_expr, ast.Call)
        and resolve_binding_fn(seed_expr.func) == "builtins.bytearray"
        and len(seed_expr.args) == 1
        and not seed_expr.keywords
        and isinstance(seed_expr.args[0], ast.Constant)
        and type(seed_expr.args[0].value) is bytes
    )


_BUILTIN_TYPE_NAMES = {"int", "str", "float", "bool", "bytes", "object", "Any", "dict", "list", "set", "tuple"}
_ALLOWED_EMPTY_BASE_SUFFIXES = ("Error", "Exception", "Warning", "Protocol", "ABC")
_FORBIDDEN_FRAME_ATTRS = {"__code__", "co_varnames", "co_names", "f_locals", "f_globals", "f_back", "_getframe", "currentframe"}
_DEGENERATE_CONSTANTS = {0, 0.0, "", None}
_DEFAULT_SYMBOL_BINDINGS: dict[str, str] = {
    "open": "builtins.open", "staticmethod": "builtins.staticmethod", "list": "builtins.list",
    "dict": "builtins.dict", "set": "builtins.set", "tuple": "builtins.tuple",
    "frozenset": "builtins.frozenset", "sorted": "builtins.sorted", "bytearray": "builtins.bytearray",
    "setattr": "builtins.setattr", "delattr": "builtins.delattr",
}
_TRACKED_IMPORT_TARGETS: dict[tuple[str, str], str] = {
    ("builtins", "staticmethod"): "builtins.staticmethod", ("builtins", "open"): "builtins.open",
    ("builtins", "list"): "builtins.list", ("builtins", "dict"): "builtins.dict",
    ("builtins", "set"): "builtins.set", ("builtins", "tuple"): "builtins.tuple",
    ("builtins", "frozenset"): "builtins.frozenset", ("builtins", "sorted"): "builtins.sorted",
    ("builtins", "bytearray"): "builtins.bytearray", ("builtins", "setattr"): "builtins.setattr",
    ("builtins", "delattr"): "builtins.delattr", ("typing", "overload"): "typing.overload",
    ("typing_extensions", "overload"): "typing.overload", ("typing", "TYPE_CHECKING"): "typing.TYPE_CHECKING",
    ("typing_extensions", "TYPE_CHECKING"): "typing.TYPE_CHECKING", ("abc", "abstractmethod"): "abc.abstractmethod",
    ("functools", "wraps"): "functools.wraps", ("datetime", "datetime"): "datetime.datetime",
    ("datetime", "date"): "datetime.date", ("os", "environ"): "os.environ",
    ("pathlib", "Path"): "pathlib.Path", ("random", "Random"): "random.Random",
    ("random", "SystemRandom"): "random.SystemRandom",
}
_TRACKED_MODULE_PREFIXES = {
    "builtins", "typing", "typing_extensions", "abc", "functools", "datetime",
    "time", "random", "secrets", "uuid", "os", "pathlib",
}


def _is_degenerate_expr(expr: ast.AST | None) -> bool:
    if expr is None or (isinstance(expr, ast.Constant) and expr.value in _DEGENERATE_CONSTANTS and expr.value is not False):
        return True
    if isinstance(expr, (ast.Dict, ast.List, ast.Set, ast.Tuple)):
        return len(getattr(expr, "elts", getattr(expr, "keys", []))) == 0
    return False


def _iter_assigned_names(target: ast.AST) -> list[str]:
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        return [n for elt in target.elts for n in _iter_assigned_names(elt)]
    if isinstance(target, ast.Starred):
        return _iter_assigned_names(target.value)
    return []


def _build_param_key(args: ast.arguments, drop_receiver: bool) -> tuple[tuple[str, str], ...]:
    pos = [("posonly", a.arg) for a in args.posonlyargs] + [("arg", a.arg) for a in args.args]
    if drop_receiver and pos:
        pos = pos[1:]
    kwonly = [("kwonly", a.arg) for a in args.kwonlyargs]
    var_p = ([("vararg", args.vararg.arg)] if args.vararg else []) + ([("kwarg", args.kwarg.arg)] if args.kwarg else [])
    return tuple(pos + kwonly + var_p)


def count_effective_params(
    node: ast.FunctionDef | ast.AsyncFunctionDef, parent_scope: ScopeKind, resolved_decorators: set[str]
) -> tuple[int, bool]:
    pos_count = len(node.args.posonlyargs) + len(node.args.args)
    total = pos_count + len(node.args.kwonlyargs)
    drop_receiver = parent_scope == ScopeKind.CLASS and "builtins.staticmethod" not in resolved_decorators and pos_count >= 1
    return (total - 1 if drop_receiver else total), drop_receiver


def _calls_target_with_varargs(func_node: ast.FunctionDef | ast.AsyncFunctionDef, target_name: str) -> bool:
    v_name = func_node.args.vararg.arg if func_node.args.vararg else None
    k_name = func_node.args.kwarg.arg if func_node.args.kwarg else None
    for sub in ast.walk(func_node):
        if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name) and sub.func.id == target_name:
            f_star = v_name is None or any(isinstance(a, ast.Starred) and isinstance(a.value, ast.Name) and a.value.id == v_name for a in sub.args)
            f_kw = k_name is None or any(kw.arg is None and isinstance(kw.value, ast.Name) and kw.value.id == k_name for kw in sub.keywords)
            if f_star and f_kw:
                return True
    return False


def _is_version_or_platform_guard(test: ast.AST) -> bool:
    return any(
        (isinstance(s, ast.Attribute) and s.attr in ("version_info", "platform"))
        or (isinstance(s, ast.Name) and s.id in ("version_info", "platform"))
        for s in ast.walk(test)
    )


def _is_import_error_handler(handler: ast.ExceptHandler) -> bool:
    if isinstance(handler.type, ast.Name):
        return handler.type.id in ("ImportError", "ModuleNotFoundError")
    if isinstance(handler.type, ast.Tuple):
        return all(isinstance(el, ast.Name) and el.id in ("ImportError", "ModuleNotFoundError") for el in handler.type.elts)
    return False


def _is_top_level_optional_import_try(node: ast.AST) -> bool:
    handlers = getattr(node, "handlers", ())
    body = getattr(node, "body", ())
    return bool(handlers) and all(_is_import_error_handler(h) for h in handlers) and any(isinstance(s, (ast.Import, ast.ImportFrom)) for s in body)


def _check_empty_subclass_rules(node: ast.ClassDef, record_fn: Callable[[int, str, str], None]) -> None:
    body_wo_doc = [s for s in node.body if not (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant) and isinstance(s.value.value, str))]
    if len(body_wo_doc) == 1 and isinstance(body_wo_doc[0], ast.Pass):
        base_names = [b.attr if isinstance(b, ast.Attribute) else (b.id if isinstance(b, ast.Name) else "") for b in node.bases]
        if not any(bn.endswith(_ALLOWED_EMPTY_BASE_SUFFIXES) for bn in base_names):
            record_fn(node.lineno, "symbol_alias_bloat", f"Empty subclass alias '{node.name}' is forbidden (Zero-S2).")


def _check_passthrough_wrapper_rules(
    node: ast.FunctionDef | ast.AsyncFunctionDef, drop_receiver: bool, qualname: str, record_fn: Callable[[int, str, str], None]
) -> None:
    all_args = list(node.args.posonlyargs) + list(node.args.args) + list(node.args.kwonlyargs)
    if drop_receiver and all_args:
        all_args = all_args[1:]
    body_wo_doc = [s for s in node.body if not (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant) and isinstance(s.value.value, str))]
    if len(body_wo_doc) == 1 and isinstance(body_wo_doc[0], ast.Return) and isinstance(body_wo_doc[0].value, ast.Call):
        call = body_wo_doc[0].value
        param_names = {a.arg for a in all_args}
        forwarded = {a.id for a in call.args if isinstance(a, ast.Name)} | {kw.value.id for kw in call.keywords if isinstance(kw.value, ast.Name)}
        if len(param_names) >= 3 and forwarded == param_names:
            record_fn(node.lineno, "passthrough_wrapper_bloat", f"Pass-through wrapper '{qualname}' forwarding {len(param_names)} args 1:1 is forbidden (Zero-S2).")


def _check_try_statement_rules(try_node: ast.Try, trailing_stmts: list[ast.stmt], record_fn: Callable[[int, str, str], None]) -> None:
    for handler in try_node.handlers:
        exc_name = handler.type.id if isinstance(handler.type, ast.Name) else ""
        if exc_name == "AttributeError":
            record_fn(handler.lineno, "defensive_getattr_slop", "Catching AttributeError in production code is forbidden (Zero-S1). Fix the static type contract.")
        is_broad = handler.type is None or exc_name in ("Exception", "BaseException")
        if is_broad and not any(isinstance(n, ast.Raise) for n in ast.walk(handler)):
            for sub in ast.walk(handler):
                if isinstance(sub, ast.Return) and _is_degenerate_expr(sub.value):
                    record_fn(sub.lineno, "swallowed_fallback_return", "Returning degenerate fallback (0/0.0/{}/[]/None) from broad except is forbidden (Zero-S4).")
            if trailing_stmts and isinstance(trailing_stmts[0], ast.Return):
                record_fn(handler.lineno, "swallowed_fallback_return", "Swallowing broad Exception and returning fallback variable after try/except is forbidden (Zero-S4).")


def _nesting_for_if(node: ast.If, depth: int) -> int:
    next_d = depth + 1
    best = max(next_d, compute_max_control_nesting_depth(node.body, next_d))
    if len(node.orelse) == 1 and isinstance(node.orelse[0], ast.If):
        return max(best, _nesting_for_if(node.orelse[0], depth))
    if node.orelse:
        return max(best, compute_max_control_nesting_depth(node.orelse, next_d))
    return best


def compute_max_control_nesting_depth(stmts: Sequence[ast.stmt], depth: int = 0) -> int:
    best = depth
    for stmt in stmts:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if isinstance(stmt, ast.If):
            best = max(best, _nesting_for_if(stmt, depth))
        elif isinstance(stmt, (ast.For, ast.AsyncFor, ast.While)):
            nd = depth + 1
            best = max(best, nd, compute_max_control_nesting_depth(stmt.body, nd), compute_max_control_nesting_depth(stmt.orelse, nd))
        elif isinstance(stmt, (ast.With, ast.AsyncWith)):
            nd = depth + 1
            best = max(best, nd, compute_max_control_nesting_depth(stmt.body, nd))
        elif isinstance(stmt, _TRY_NODE_TYPES):
            nd = depth + 1
            best = max(
                best, nd,
                compute_max_control_nesting_depth(getattr(stmt, "body", ()), nd),
                compute_max_control_nesting_depth(getattr(stmt, "orelse", ()), nd),
                compute_max_control_nesting_depth(getattr(stmt, "finalbody", ()), nd),
            )
            for h in getattr(stmt, "handlers", ()):
                best = max(best, compute_max_control_nesting_depth(h.body, nd))
        elif _MATCH_NODE_TYPES and isinstance(stmt, _MATCH_NODE_TYPES):
            nd = depth + 1
            best = max(best, nd)
            for case in getattr(stmt, "cases", ()):
                best = max(best, compute_max_control_nesting_depth(case.body, nd))
    return best


def _compare_variant_pair(
    filename: str, lines: list[str], base_v: FunctionVariantMetrics | None, target_v: FunctionVariantMetrics
) -> list[SlopViolation]:
    out: list[SlopViolation] = []
    snip = lines[target_v.lineno - 1].strip()[:100] if 1 <= target_v.lineno <= len(lines) else ""
    allowed_params = MAX_FUNCTION_ARGS if base_v is None else max(MAX_FUNCTION_ARGS, base_v.effective_params)
    if target_v.effective_params > allowed_params:
        msg = f"Function '{target_v.qualname}' has {target_v.effective_params} parameters (allowed ceiling {allowed_params}). Pass a frozen @dataclass DTO."
        out.append(SlopViolation(filename, target_v.lineno, "excessive_parameter_list", msg, snip))
    if target_v.has_unjustified_varargs and (base_v is None or not base_v.has_unjustified_varargs):
        msg = f"Function '{target_v.qualname}' introduces *args/**kwargs without a valid @wraps closure."
        out.append(SlopViolation(filename, target_v.lineno, "excessive_parameter_list", msg, snip))
    allowed_depth = MAX_CONTROL_NESTING_DEPTH if base_v is None else max(MAX_CONTROL_NESTING_DEPTH, base_v.max_nesting_depth)
    if target_v.max_nesting_depth > allowed_depth:
        msg = f"Function '{target_v.qualname}' has control nesting depth {target_v.max_nesting_depth} (allowed ceiling {allowed_depth}) (Zero-C1)."
        out.append(SlopViolation(filename, target_v.lineno, "excessive_nesting_depth", msg, snip))
    base_counts = {} if base_v is None else base_v.body_count_map()
    for cat, t_cnt in target_v.body_counts:
        b_cnt = base_counts.get(cat, 0)
        if t_cnt > b_cnt:
            msg = f"Function '{target_v.qualname}' worsened '{cat}' ({b_cnt} -> {t_cnt})."
            out.append(SlopViolation(filename, target_v.lineno, cat, msg, snip))
    return out


def _match_variants_by_predicate(
    base_list: list[FunctionVariantMetrics],
    target_list: list[FunctionVariantMetrics],
    used_base: set[int],
    matched_target: dict[int, FunctionVariantMetrics | None],
    same_context: bool,
    same_profile: bool,
) -> None:
    for t_idx, tv in enumerate(target_list):
        if t_idx in matched_target:
            continue
        for b_idx, bv in enumerate(base_list):
            if b_idx in used_base:
                continue
            if same_profile and tv.unchanged_profile_key != bv.unchanged_profile_key:
                continue
            if same_context and tv.variant_context != bv.variant_context:
                continue
            used_base.add(b_idx)
            matched_target[t_idx] = bv
            break


def _match_remaining_variants_by_arity(
    base_list: list[FunctionVariantMetrics],
    target_list: list[FunctionVariantMetrics],
    used_base: set[int],
    matched_target: dict[int, FunctionVariantMetrics | None],
) -> None:
    rem_t = sorted((i for i in range(len(target_list)) if i not in matched_target), key=lambda i: (-target_list[i].effective_params, -target_list[i].max_nesting_depth, i))
    rem_b = sorted((i for i in range(len(base_list)) if i not in used_base), key=lambda i: (-base_list[i].effective_params, -base_list[i].max_nesting_depth, i))
    for t_idx, b_idx in zip(rem_t, rem_b):
        used_base.add(b_idx)
        matched_target[t_idx] = base_list[b_idx]


def _pair_runtime_variants(
    base_list: list[FunctionVariantMetrics], target_list: list[FunctionVariantMetrics]
) -> list[tuple[FunctionVariantMetrics | None, FunctionVariantMetrics]]:
    used_base: set[int] = set()
    matched_target: dict[int, FunctionVariantMetrics | None] = {}
    _match_variants_by_predicate(base_list, target_list, used_base, matched_target, same_context=True, same_profile=True)
    _match_variants_by_predicate(base_list, target_list, used_base, matched_target, same_context=True, same_profile=False)
    _match_variants_by_predicate(base_list, target_list, used_base, matched_target, same_context=False, same_profile=True)
    _match_remaining_variants_by_arity(base_list, target_list, used_base, matched_target)
    return [(matched_target.get(t_idx), tv) for t_idx, tv in enumerate(target_list)]


def _pair_overload_variants(
    base_list: list[FunctionVariantMetrics], target_list: list[FunctionVariantMetrics]
) -> list[tuple[FunctionVariantMetrics | None, FunctionVariantMetrics]]:
    used_base: set[int] = set()
    matched_target: dict[int, FunctionVariantMetrics | None] = {}
    for t_idx, tv in enumerate(target_list):
        for b_idx, bv in enumerate(base_list):
            if b_idx not in used_base and tv.param_key == bv.param_key:
                used_base.add(b_idx)
                matched_target[t_idx] = bv
                break
    candidates: list[tuple[int, int, int, int]] = []
    for t_idx, tv in enumerate(target_list):
        if t_idx in matched_target:
            continue
        t_names = {name for _, name in tv.param_key}
        for b_idx, bv in enumerate(base_list):
            if b_idx not in used_base:
                overlap = len(t_names & {name for _, name in bv.param_key})
                if overlap > 0:
                    candidates.append((overlap, -abs(tv.effective_params - bv.effective_params), t_idx, b_idx))
    for _, _, t_idx, b_idx in sorted(candidates, reverse=True):
        if t_idx not in matched_target and b_idx not in used_base:
            used_base.add(b_idx)
            matched_target[t_idx] = base_list[b_idx]
    return [(matched_target.get(t_idx), tv) for t_idx, tv in enumerate(target_list)]


def _compare_non_function_scopes(
    filename: str, lines: list[str], base_snap: ModuleAstSnapshot, target_snap: ModuleAstSnapshot
) -> list[SlopViolation]:
    out: list[SlopViolation] = []
    for (owner, cat), t_cnt in sorted(target_snap.non_function_counts.items()):
        b_cnt = base_snap.non_function_counts.get((owner, cat), 0)
        if t_cnt > b_cnt:
            lineno = target_snap.non_function_lines.get((owner, cat), 1)
            snip = lines[lineno - 1].strip()[:100] if 1 <= lineno <= len(lines) else ""
            out.append(SlopViolation(filename, lineno, cat, f"Scope '{owner}' worsened '{cat}' ({b_cnt} -> {t_cnt}).", snip))
    return out


def _summarize_function_entries(
    filename: str, qualname: str, variants: list[FunctionVariantMetrics], allowed_kinds: set[str] | None
) -> dict[tuple[str, str], dict[str, Any]]:
    out: dict[tuple[str, str], dict[str, Any]] = {}
    param_ceilings: list[int] = []
    depth_ceilings: list[int] = []
    body_totals: dict[str, int] = {}
    for v in variants:
        if v.effective_params > MAX_FUNCTION_ARGS:
            param_ceilings.append(v.effective_params)
        elif v.has_unjustified_varargs:
            param_ceilings.append(MAX_FUNCTION_ARGS + 1)
        if v.max_nesting_depth > MAX_CONTROL_NESTING_DEPTH:
            depth_ceilings.append(v.max_nesting_depth)
        for cat, cnt in v.body_counts:
            if cat == "excessive_parameter_list":
                param_ceilings.extend([MAX_FUNCTION_ARGS + 1] * cnt)
            else:
                body_totals[cat] = body_totals.get(cat, 0) + cnt

    for kind, ceilings in (("excessive_parameter_list", param_ceilings), ("excessive_nesting_depth", depth_ceilings)):
        if ceilings and (allowed_kinds is None or kind in allowed_kinds):
            ceilings.sort(reverse=True)
            entry: dict[str, Any] = {"file": filename, "symbol": qualname, "kind": kind, "ceiling": ceilings[0], "occurrences": len(ceilings)}
            if len(ceilings) > 1:
                entry["variant_ceilings"] = ceilings
            out[(qualname, kind)] = entry

    for cat, cnt in sorted(body_totals.items()):
        if allowed_kinds is None or cat in allowed_kinds:
            out[(qualname, cat)] = {"file": filename, "symbol": qualname, "kind": cat, "ceiling": cnt, "occurrences": cnt}
    return out


_SNAPSHOT_EXTRACTOR: Callable[[str, str, Sequence[dict[str, Any]]], ModuleAstSnapshot] | None = None


def register_snapshot_extractor(fn: Callable[[str, str, Sequence[dict[str, Any]]], ModuleAstSnapshot]) -> None:
    global _SNAPSHOT_EXTRACTOR
    _SNAPSHOT_EXTRACTOR = fn


def _extractor() -> Callable[[str, str, Sequence[dict[str, Any]]], ModuleAstSnapshot]:
    if _SNAPSHOT_EXTRACTOR is None:  # explicit check: an `assert` vanishes under `python -O`
        raise GuardAnalysisError("AST snapshot extractor not registered (import agent_ratchet.refactoring_guard)")
    return _SNAPSHOT_EXTRACTOR


def compare_ast_snapshots(
    base_source: str | None, target_source: str, filename: str, extra_rules: Sequence[dict[str, Any]] = ()
) -> list[SlopViolation]:
    if not filename.endswith(".py") or is_self_skipped(filename, fixture_paths=NO_FIXTURES):  # fixtures filtered by caller / is_test_filename
        return []
    extract = _extractor()
    target_snap = extract(target_source, filename, extra_rules)
    if target_snap.parse_error is not None:
        return list(target_snap.full_violations)
    base_snap = (
        ModuleAstSnapshot(filename, None, 0, {}, {}, {}, {}, [])
        if base_source is None
        else extract(base_source, filename, extra_rules)
    )
    if base_snap.parse_error is not None:
        return [SlopViolation(filename, base_snap.parse_lineno, "guard_analysis_error", f"Base snapshot failed AST parse: {base_snap.parse_error}", "")]

    lines = target_source.splitlines()
    violations = _compare_non_function_scopes(filename, lines, base_snap, target_snap)
    for qualname, t_variants in sorted(target_snap.runtime_variants.items()):
        for bv, tv in _pair_runtime_variants(base_snap.runtime_variants.get(qualname, []), t_variants):
            violations.extend(_compare_variant_pair(filename, lines, bv, tv))
    for qualname, t_overloads in sorted(target_snap.overload_variants.items()):
        for bv, tv in _pair_overload_variants(base_snap.overload_variants.get(qualname, []), t_overloads):
            violations.extend(_compare_variant_pair(filename, lines, bv, tv))
    return violations


def collect_refactoring_slop_entries(
    source: str, filename: str, extra_rules: Sequence[dict[str, Any]] = (), allowed_kinds: set[str] | None = None
) -> list[dict[str, Any]]:
    snap = _extractor()(source, filename, extra_rules)
    if snap.parse_error is not None:
        raise GuardAnalysisError(f"{filename}:{snap.parse_lineno}: {snap.parse_error}")
    entries_by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for (owner, cat), cnt in sorted(snap.non_function_counts.items()):
        if allowed_kinds is None or cat in allowed_kinds:
            entries_by_key[(owner, cat)] = {"file": filename, "symbol": owner, "kind": cat, "ceiling": cnt, "occurrences": cnt}
    for qualname in sorted(set(snap.runtime_variants) | set(snap.overload_variants)):
        variants = list(snap.runtime_variants.get(qualname, [])) + list(snap.overload_variants.get(qualname, []))
        entries_by_key.update(_summarize_function_entries(filename, qualname, variants, allowed_kinds))
    return [entries_by_key[k] for k in sorted(entries_by_key)]


__all__ = [
    "BranchKind", "DUMPING_GROUND_FILENAME_RE", "ExitKind", "FORBIDDEN_DOMAIN_CALL_TARGETS",
    "FORBIDDEN_DOMAIN_IMPORT_MODULES", "FORBIDDEN_DOMAIN_LAYER_SEGMENTS", "FORBIDDEN_PATH_DISK_METHODS",
    "FunctionVariantMetrics", "MUTATING_COLLECTION_METHODS", "ModuleAstSnapshot", "ScopeKind", "_FlowState",
    "_ScopeFrame", "_compare_non_function_scopes", "_compare_variant_pair", "_join_flow_states",
    "_pair_overload_variants", "_pair_runtime_variants", "_restore_flow_state", "_snapshot_flow_state",
    "_summarize_function_entries", "check_staged_file_size_buffer", "collect_refactoring_slop_entries",
    "compare_ast_snapshots", "compute_max_control_nesting_depth", "evaluate_loc_transition",
    "extract_changed_lines_map", "git_cat_bytes", "git_show_text", "is_domain_file", "is_query_function_name",
    "is_safe_local_container_allocation", "is_valid_deterministic_random_seed_call", "register_snapshot_extractor",
]


def _names_outside_calls(expr: ast.AST) -> list[str]:
    """Names reachable without entering a call: a call's result is a fresh value, not an alias of its arguments."""
    if isinstance(expr, ast.Call):
        return []
    if isinstance(expr, ast.Name):
        return [expr.id]
    return [name for child in ast.iter_child_nodes(expr) for name in _names_outside_calls(child)]
