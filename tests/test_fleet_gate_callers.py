"""Every profile-predicate use under src/agent_ratchet must be a gate the fleet classifier recognises, and every
gate that takes its config as a parameter must be reached only with a config the loader produced."""

from __future__ import annotations

import ast
from pathlib import Path

from fleet_import import guard_fleet, load_tree_from_worktree, tree_from

guard_fleet()

from guard_fleet.classify.gating import LOADER, PREDICATE  # noqa: E402
from guard_fleet.classify.surfaces import compute_surfaces  # noqa: E402
from guard_fleet.classify.tree import SourceTree, module_name  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
LOADER_NAMES = frozenset({LOADER, "_read_guard_config_for_ref"})

# Predicate uses that are not import gates. Keep this list as short as the code allows.
KNOWN_NON_GATES = {
    # The predicate's own body (`"php" in ... or "magento" in cfg.get("frameworks", ())`): the definition, not a gate.
    ("agent_ratchet.php.scope", 72),
}


def _module_of(path: Path, src_root: Path) -> str:
    parts = list(path.relative_to(src_root).with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _is_magento_membership(node: ast.AST) -> bool:
    """`"magento" in|not in <x>.get("frameworks", ...)`."""
    if not (isinstance(node, ast.Compare) and len(node.ops) == 1 and isinstance(node.ops[0], (ast.In, ast.NotIn))):
        return False
    left, right = node.left, node.comparators[0]
    return (isinstance(left, ast.Constant) and left.value == "magento" and isinstance(right, ast.Call)
            and isinstance(right.func, ast.Attribute) and right.func.attr == "get" and bool(right.args)
            and isinstance(right.args[0], ast.Constant) and right.args[0].value == "frameworks")


def _is_predicate_call(node: ast.AST) -> bool:
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    return (isinstance(func, ast.Name) and func.id == PREDICATE) or (isinstance(func, ast.Attribute) and func.attr == PREDICATE)


def predicate_call_sites(package_dir: Path) -> set[tuple[str, int]]:
    """(module, lineno) of every `php_profile_active(...)` call and every magento `frameworks` membership test."""
    src_root = package_dir.parent
    sites: set[tuple[str, int]] = set()
    for path in sorted(package_dir.rglob("*.py")):
        module = _module_of(path, src_root)
        for node in ast.walk(ast.parse(path.read_bytes(), filename=str(path))):
            if _is_predicate_call(node) or _is_magento_membership(node):
                sites.add((module, node.lineno))
    return sites


# -- parameter-gated callers ---------------------------------------------------------------------------

def _modules(tree: SourceTree) -> dict[str, ast.Module]:
    out: dict[str, ast.Module] = {}
    for path, raw in tree.files.items():
        name = module_name(path)
        if name is not None:
            out[name] = ast.parse(raw, filename=path)
    return out


def _functions(module: ast.Module) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
    return [n for n in ast.walk(module) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]


def _params(func: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    a = func.args
    return [p.arg for p in (*a.posonlyargs, *a.args, *a.kwonlyargs)]


def _gate_argument(test: ast.expr) -> str | None:
    """The Name the gate's test reads: `php_profile_active(<Name>)` or `<Name>.get("frameworks", ())`."""
    for node in ast.walk(test):
        if _is_predicate_call(node) and node.args and isinstance(node.args[0], ast.Name):
            return node.args[0].id
        if _is_magento_membership(node):
            call = node.comparators[0]
            if isinstance(call.func.value, ast.Name):
                return call.func.value.id
    return None


def _assigned_values(func: ast.FunctionDef | ast.AsyncFunctionDef, name: str) -> list[ast.expr]:
    return [n.value for n in ast.walk(func)
            if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in n.targets)]


def _is_loader_call(node: ast.expr) -> bool:
    return isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in LOADER_NAMES


def _bound_from_loader(func: ast.FunctionDef | ast.AsyncFunctionDef | None, expr: ast.expr) -> bool:
    """`expr` is a loader call, or a Name assigned once from a loader call or (one hop) from such a Name."""
    if _is_loader_call(expr):
        return True
    if func is None or not isinstance(expr, ast.Name) or expr.id in _params(func):
        return False
    values = _assigned_values(func, expr.id)
    if len(values) != 1:
        return False
    value = values[0]
    if _is_loader_call(value):
        return True
    if isinstance(value, ast.Name) and value.id not in _params(func):
        inner = _assigned_values(func, value.id)
        return len(inner) == 1 and _is_loader_call(inner[0])
    return False


def _calls_of(modules: dict[str, ast.Module], gate_module: str, name: str):
    """Yield (caller module, enclosing function or None, call) for every call that can reach `gate_module.name`."""
    for mod_name, module in modules.items():
        imported_as = {name} if mod_name == gate_module else set()
        for node in module.body:
            if isinstance(node, ast.ImportFrom) and node.module == gate_module:
                imported_as |= {a.asname or a.name for a in node.names if a.name == name}
        enclosing: dict[int, ast.FunctionDef | ast.AsyncFunctionDef] = {}
        for func in _functions(module):
            for inner in ast.walk(func):
                enclosing[id(inner)] = func   # the innermost function wins: functions are visited outermost first
        for node in ast.walk(module):
            if not isinstance(node, ast.Call):
                continue
            hit = (isinstance(node.func, ast.Name) and node.func.id in imported_as) or (
                isinstance(node.func, ast.Attribute) and node.func.attr == name)
            if hit:
                yield mod_name, enclosing.get(id(node)), node


def untraced_gate_parameters(tree: SourceTree) -> list[tuple[str, int]]:
    """(module, lineno) of every call that reaches a parameter-gated function with a value the loader did not
    produce. A gate is parameter-gated when its test reads one of its function's own parameters."""
    modules = _modules(tree)
    untraced: list[tuple[str, int]] = []
    for gate in compute_surfaces(tree).gates:
        funcs = [f for f in _functions(modules[gate.module]) if f.name == gate.func.rsplit(".", 1)[-1]]
        for func in funcs:
            gate_if = next((n for n in ast.walk(func) if isinstance(n, ast.If) and n.lineno == gate.lineno), None)
            arg = _gate_argument(gate_if.test) if gate_if is not None else None
            if arg is None or arg not in _params(func):
                continue
            position = _params(func).index(arg)
            for caller, caller_func, call in _calls_of(modules, gate.module, func.name):
                if position < len(call.args):
                    passed = call.args[position]
                else:
                    passed = next((kw.value for kw in call.keywords if kw.arg == arg), None)
                if passed is None or not _bound_from_loader(caller_func, passed):
                    untraced.append((caller, call.lineno))
    return sorted(set(untraced))


# -- tests ------------------------------------------------------------------------------------------

def test_every_predicate_call_is_a_recognised_gate():
    gates = compute_surfaces(load_tree_from_worktree(ROOT)).gates
    sites = {(g.module, g.lineno) for g in gates}
    found = predicate_call_sites(ROOT / "src" / "agent_ratchet")
    assert sites, "the classifier recognised no gate at all"
    assert KNOWN_NON_GATES <= found, "stale KNOWN_NON_GATES entry"
    assert found <= sites | KNOWN_NON_GATES, sorted(found - sites - KNOWN_NON_GATES)
    assert sites <= found, sorted(sites - found)


def test_parameter_gated_callers_pass_loader_config():
    assert untraced_gate_parameters(load_tree_from_worktree(ROOT)) == []


_PRED = "from agent_ratchet.php.scope import php_profile_active\n"
_GATED = _PRED + "def run(cfg):\n    if php_profile_active(cfg):\n        from agent_ratchet.php import x\n"


def test_parameter_gated_caller_with_literal_dict_fails():
    tree = tree_from({"src/agent_ratchet/a.py": _GATED,
                      "src/agent_ratchet/b.py": "from agent_ratchet.a import run\nrun({'profiles': ['php']})\n"})
    assert untraced_gate_parameters(tree) == [("agent_ratchet.b", 2)]


def test_parameter_gated_caller_with_own_parameter_fails():
    tree = tree_from({"src/agent_ratchet/a.py": _GATED,
                      "src/agent_ratchet/b.py": "from agent_ratchet.a import run\ndef go(cfg):\n    run(cfg)\n"})
    assert untraced_gate_parameters(tree) == [("agent_ratchet.b", 3)]


def test_parameter_gated_callers_with_loader_values_pass():
    tree = tree_from({
        "src/agent_ratchet/a.py": _GATED,
        "src/agent_ratchet/b.py": (
            "from agent_ratchet.a import run\n"
            "from agent_ratchet.git_guard_io import load_guard_config_for_ref\n"
            "def direct(ref):\n    run(load_guard_config_for_ref(ref))\n"
            "def one_hop(ref):\n    cfg = load_guard_config_for_ref(ref)\n    run(cfg)\n"
            "def two_hops(ref):\n    cfg = load_guard_config_for_ref(ref)\n    again = cfg\n    run(cfg=again)\n"
        ),
    })
    assert untraced_gate_parameters(tree) == []


def test_locally_bound_gate_needs_no_caller_trace():
    local = (_PRED + "from agent_ratchet.git_guard_io import load_guard_config_for_ref\n"
             "def run(ref):\n    cfg = load_guard_config_for_ref(ref)\n    if php_profile_active(cfg):\n"
             "        from agent_ratchet.php import x\n")
    tree = tree_from({"src/agent_ratchet/a.py": local,
                      "src/agent_ratchet/b.py": "from agent_ratchet.a import run\nrun({'profiles': ['php']})\n"})
    assert [g.module for g in compute_surfaces(tree).gates] == ["agent_ratchet.a"]
    assert untraced_gate_parameters(tree) == []
