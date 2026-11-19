"""Deep or recursive AST input fails closed: GuardAnalysisError (exit 2, guard_analysis_error), never a traceback or a silent pass."""

from __future__ import annotations

import ast
from pathlib import Path
import sys
from typing import Callable

import pytest

from agent_ratchet import ast_topology_guard, cognitive_complexity, git_guard_io, refactoring_guard
from agent_ratchet.ai_slop_scanner import _py_entry_needs_a2
from agent_ratchet.ast_topology_guard import tarjan_scc
from agent_ratchet.git_guard_io import GuardAnalysisError, count_test_assertions, parse_python, visit_bounded

sys.path.insert(0, str(Path(__file__).resolve().parent))
from guard_repo_harness import _commit_files, _git, _init_guard_repo, _run_scanner, _write_files

# ast.parse itself raises RecursionError ("during ast construction") on 3.11; exercises parse_python.
DEEP_PARSE = "x = " + "+".join(["1"] * 100_000) + "\n"
# Parses fine, but NodeVisitor / compile recurse past the limit; exercises visit_bounded.
DEEP_VISIT = "x = " + "+".join(["1"] * 1_000) + "\n"
SHALLOW = "x = 1\n"
SYNTAX_ERROR_EXIT = 2  # pinned from the unmodified 3.3.0 run: syntax_error rule, not the A2 probe
DEEP_SOURCES = pytest.mark.parametrize("deep", [DEEP_PARSE, DEEP_VISIT], ids=["parse", "visit"])


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    r = _init_guard_repo(str(tmp_path))
    _commit_files(r, "chore: initial", {
        "src/deep.py": SHALLOW,
        "tests/test_deep.py": "def test_a():\n    assert 1\n",
    }, include_guards=True)
    return r


def _assert_fails_closed(rc: int, stdout: str, stderr: str) -> None:
    assert rc == 2, (stdout, stderr[-2000:])
    assert "guard_analysis_error" in stderr + stdout
    assert "Traceback" not in stderr


@DEEP_SOURCES
def test_deep_ast_staged_scan_fails_closed(repo: Path, deep: str) -> None:
    _write_files(repo, {"src/deep.py": deep})
    _git(repo, "add", "src/deep.py")
    r = _run_scanner(repo, "--staged-only")
    _assert_fails_closed(r.returncode, r.stdout, r.stderr)
    assert "src/deep.py: AST too deep to analyse" in r.stderr


@DEEP_SOURCES
def test_deep_ast_diff_base_scan_fails_closed(repo: Path, deep: str) -> None:
    base = _git(repo, "rev-parse", "HEAD")
    _commit_files(repo, "feat: deepen", {"src/deep.py": deep})
    r = _run_scanner(repo, "--diff-base", base)
    _assert_fails_closed(r.returncode, r.stdout, r.stderr)


@DEEP_SOURCES
def test_deep_ast_test_file_staged_scan_fails_closed(repo: Path, deep: str) -> None:
    _write_files(repo, {"tests/test_deep.py": "def test_a():\n    assert 1\n" + deep})
    _git(repo, "add", "tests/test_deep.py")
    r = _run_scanner(repo, "--staged-only")
    _assert_fails_closed(r.returncode, r.stdout, r.stderr)


@DEEP_SOURCES
def test_deep_ast_topology_fails_closed(deep: str) -> None:
    with pytest.raises(GuardAnalysisError, match="AST too deep to analyse"):
        ast_topology_guard.extract_module_import_facts(deep, "src/deep.py")


@DEEP_SOURCES
def test_deep_ast_refactoring_snapshot_fails_closed(deep: str) -> None:
    with pytest.raises(GuardAnalysisError, match="AST too deep to analyse"):
        refactoring_guard.extract_ast_snapshot(deep, "src/deep.py")


def test_a2_probe_propagates_recursion_error(repo: Path) -> None:
    base = _git(repo, "rev-parse", "HEAD")
    head = _commit_files(repo, "feat: deepen", {"src/deep.py": DEEP_PARSE})
    r = _run_scanner(repo, "--commit-range", f"{base}..{head}")
    _assert_fails_closed(r.returncode, r.stdout, r.stderr)
    assert "AST too deep" in r.stderr


def test_a2_probe_unit_propagates_recursion_error() -> None:
    # compare_ast_snapshots raises first end to end, so the probe's own narrowing is pinned directly.
    for base, target in (("x = 1\n", DEEP_PARSE), (DEEP_PARSE, "x = 1\n"), ("x = 1\n", DEEP_VISIT)):
        with pytest.raises(GuardAnalysisError, match="AST too deep"):
            _py_entry_needs_a2("M", "src/x.py", "src/x.py", base, target)


def test_a2_probe_unit_tolerates_syntax_error() -> None:
    assert _py_entry_needs_a2("M", "src/x.py", "src/x.py", "x = 1\n", "def (:\n") is False


def test_a2_probe_still_tolerates_syntax_error(repo: Path) -> None:
    base = _git(repo, "rev-parse", "HEAD")
    head = _commit_files(repo, "feat: break", {"src/deep.py": "def (:\n"})
    r = _run_scanner(repo, "--commit-range", f"{base}..{head}")
    assert (r.returncode, "Traceback" in r.stderr) == (SYNTAX_ERROR_EXIT, False), (r.stdout, r.stderr[-2000:])


def test_deep_ast_cognitive_fails_closed() -> None:
    # Cognitive scoring walks expressions iteratively, so only the parse stage can overflow (DEEP_VISIT scores fine).
    with pytest.raises(GuardAnalysisError, match="AST too deep to analyse"):
        cognitive_complexity.evaluate_cognitive_budget("src/deep.py", None, DEEP_PARSE)
    with pytest.raises(GuardAnalysisError, match="AST too deep to analyse"):
        cognitive_complexity.evaluate_cognitive_budget("src/deep.py", DEEP_PARSE, SHALLOW)
    assert cognitive_complexity.evaluate_cognitive_budget("src/deep.py", None, DEEP_VISIT)[0] == []


@DEEP_SOURCES
def test_deep_ast_test_assertions_fails_closed(deep: str) -> None:
    for strict in (False, True):
        with pytest.raises(GuardAnalysisError, match="AST too deep to analyse"):
            count_test_assertions(deep, "tests/test_deep.py", strict=strict)


def test_test_assertions_non_strict_still_ignores_syntax_error() -> None:
    assert count_test_assertions("def (:\n", "tests/test_x.py", strict=False) == 0


def test_parse_python_passes_syntax_error_through() -> None:
    with pytest.raises(SyntaxError):
        parse_python("def (:\n", "src/x.py")


def test_parse_python_accepts_bytes_and_returns_module() -> None:
    assert isinstance(parse_python(b"x = 1\n", "src/x.py"), ast.Module)


def test_parse_python_maps_memory_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*args: object, **kwargs: object) -> ast.Module:
        raise MemoryError

    monkeypatch.setattr(ast, "parse", boom)
    with pytest.raises(GuardAnalysisError, match=r"src/x\.py: AST too deep to analyse"):
        parse_python("x = 1\n", "src/x.py")


def test_visit_bounded_returns_result_and_maps_recursion_error() -> None:
    assert visit_bounded(lambda: 7, "src/x.py") == 7

    def recurse() -> None:
        recurse()

    with pytest.raises(GuardAnalysisError, match=r"src/x\.py: AST too deep to analyse"):
        visit_bounded(recurse, "src/x.py")


def _reference_tarjan_scc(graph: dict[str, set[str]]) -> list[set[str]]:
    """The recursive implementation shipped through 3.2.0, kept verbatim as the order oracle."""
    index = 0
    indices: dict[str, int] = {}
    lowlink: dict[str, int] = {}
    stack: list[str] = []
    on_stack: set[str] = set()
    cycles: list[set[str]] = []

    def strongconnect(node: str) -> None:
        nonlocal index
        indices[node] = index
        lowlink[node] = index
        index += 1
        stack.append(node)
        on_stack.add(node)
        for nbr in sorted(graph.get(node, ())):
            if nbr not in graph:
                continue
            if nbr not in indices:
                strongconnect(nbr)
                lowlink[node] = min(lowlink[node], lowlink[nbr])
            elif nbr in on_stack:
                lowlink[node] = min(lowlink[node], indices[nbr])
        if lowlink[node] == indices[node]:
            scc: set[str] = set()
            while True:
                w = stack.pop()
                on_stack.remove(w)
                scc.add(w)
                if w == node:
                    break
            if len(scc) > 1 or node in graph.get(node, ()):
                cycles.append(scc)

    for v in sorted(graph):
        if v not in indices:
            strongconnect(v)
    return cycles


_ORDER_GRAPHS: list[dict[str, set[str]]] = [
    {},
    {"a": {"a"}},
    {"a": {"b"}, "b": {"a"}, "c": {"c"}, "d": {"a", "missing"}},
    {"z": {"y"}, "y": {"x"}, "x": {"z"}, "m": {"n"}, "n": {"m", "z"}, "k": set()},
    {"a": {"b", "c"}, "b": {"d"}, "c": {"d", "e"}, "d": {"a"}, "e": {"f"}, "f": {"e", "g"}, "g": {"g"}},
    ast_topology_guard.build_snapshot_import_graph({
        "src/pkg/__init__.py": "from . import a\n",
        "src/pkg/a.py": "from . import b\n",
        "src/pkg/b.py": "from . import a\n",
        "src/pkg/c.py": "from src.pkg import c\n",
    }),
]


@pytest.mark.parametrize("graph", _ORDER_GRAPHS, ids=[f"g{i}" for i in range(len(_ORDER_GRAPHS))])
def test_tarjan_scc_order_unchanged(graph: dict[str, set[str]]) -> None:
    assert tarjan_scc(graph) == _reference_tarjan_scc(graph)


def test_tarjan_scc_iterative_handles_long_chain() -> None:
    n = 50_000
    graph: dict[str, set[str]] = {f"n{i:06d}": {f"n{i + 1:06d}"} for i in range(n - 1)}
    graph[f"n{n - 1:06d}"] = set()
    graph["c1"], graph["c2"], graph["c3"] = {"c2"}, {"c3"}, {"c1"}
    graph["n000000"].add("c1")
    sccs = tarjan_scc(graph)
    assert sccs == [{"c1", "c2", "c3"}]


def test_no_bare_ast_parse_in_package() -> None:
    """Every ast.parse in the package goes through ast_safety.parse_python (the single allow-listed call site)."""
    pkg = Path(git_guard_io.__file__).resolve().parent
    allowed = {("ast_safety.py", "parse_python")}
    offenders: list[str] = []
    for path in sorted(pkg.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        owners: dict[int, str] = {}
        for fn in ast.walk(tree):
            if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for inner in ast.walk(fn):
                    owners[id(inner)] = fn.name
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and ast.unparse(node.func) == "ast.parse":
                if (path.name, owners.get(id(node), "")) not in allowed:
                    offenders.append(f"{path.name}:{node.lineno}")
    assert offenders == []


def test_unregistered_snapshot_extractor_is_a_guard_analysis_error(monkeypatch) -> None:
    """Audit D7: fails closed with GuardAnalysisError, also under `python -O` (no bare assert)."""
    from agent_ratchet import ast_refactoring_delta
    from agent_ratchet.git_guard_io import GuardAnalysisError

    monkeypatch.setattr(ast_refactoring_delta, "_SNAPSHOT_EXTRACTOR", None)
    with pytest.raises(GuardAnalysisError, match="not registered"):
        ast_refactoring_delta.compare_ast_snapshots(None, "x = 1\n", "src/m.py")
