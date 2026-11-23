"""G7, static API compatibility: every agent_ratchet reference in the consumer at BASE resolves under T's src/."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .classify.tree import SourceTree, load_tree, module_name
from .gates import NO_LOG, GateResult
from .git import Git, GitError

ROOT = "agent_ratchet"
_WORD = re.compile(r"\bagent_ratchet\b")
_MODULE = re.compile(r"agent_ratchet(?:\.[A-Za-z_][A-Za-z0-9_]*)*")
_DASH_M = re.compile(r"(?<![\w-])-m[\s\"',]+(agent_ratchet(?:\.[A-Za-z_][A-Za-z0-9_]*)*)(?![\w.])")
SCRIPT_SUFFIXES = (".sh", ".bash", ".zsh", ".mk", ".toml", ".yml", ".yaml", ".json")
MAKEFILES = frozenset({"Makefile", "makefile", "GNUmakefile"})
_BLOCKS = (ast.If, ast.Try, ast.TryStar, ast.With, ast.AsyncWith, ast.For, ast.AsyncFor, ast.While)
_TYPE_ALIAS = getattr(ast, "TypeAlias", None)   # Python 3.12+


@dataclass(frozen=True)
class Reference:
    module: str
    name: str | None   # an imported name; None for a module reference
    origin: str        # "<path>:<line>" at BASE


def _ours(module: str | None) -> bool:
    return module is not None and (module == ROOT or module.startswith(ROOT + "."))


def _kind(path: str, raw: bytes) -> str | None:
    """"py" or "script" for the files G7 reads; None for every other file."""
    name = PurePosixPath(path).name
    if name.endswith(".py"):
        return "py"
    if name in MAKEFILES or name.endswith(SCRIPT_SUFFIXES):
        return "script"
    if "." not in name and raw.startswith(b"#!") and b"sh" in raw.split(b"\n", 1)[0]:
        return "script"   # an extensionless shell script
    return None


def _is_import_module(func: ast.expr) -> bool:
    if isinstance(func, ast.Attribute):
        return func.attr == "import_module" and isinstance(func.value, ast.Name) and func.value.id == "importlib"
    return isinstance(func, ast.Name) and func.id == "import_module"


def _python(path: str, raw: bytes, refs: list[Reference], unchecked: list[str]) -> None:
    lines = raw.decode("utf-8", errors="replace").splitlines()
    accounted: set[int] = set()
    try:
        tree = ast.parse(raw)
    except (SyntaxError, ValueError):
        tree = None
    for node in ast.walk(tree) if tree is not None else ():
        found: list[Reference] = []
        if isinstance(node, ast.Import):
            found = [Reference(a.name, None, f"{path}:{node.lineno}") for a in node.names if _ours(a.name)]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and _ours(node.module):
            assert node.module is not None
            found = [Reference(node.module, None if a.name == "*" else a.name, f"{path}:{node.lineno}")
                     for a in node.names]
        elif isinstance(node, ast.Call) and _is_import_module(node.func) and node.args:
            arg = node.args[0]
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str) and _MODULE.fullmatch(arg.value):
                found = [Reference(arg.value, None, f"{path}:{node.lineno}")]
        if found:
            refs.extend(found)
            accounted.update(range(node.lineno, (node.end_lineno or node.lineno) + 1))
    # anything else naming agent_ratchet (f-strings, computed names, comments) cannot be resolved statically
    unchecked.extend(f"not checked: {path}:{i}" for i, line in enumerate(lines, 1)
                     if _WORD.search(line) and i not in accounted)


def _script(path: str, raw: bytes, refs: list[Reference]) -> None:
    for i, line in enumerate(raw.decode("utf-8", errors="replace").splitlines(), 1):
        refs.extend(Reference(m.group(1), None, f"{path}:{i}") for m in _DASH_M.finditer(line))


def _scan(git: Git, repo: Path, base: str) -> tuple[list[Reference], list[str], list[str]]:
    grep = git(repo, "grep", "-l", "-z", "-I", "-F", "-w", "-e", ROOT, base, "--", check=False)
    if grep.rc == 1:
        return [], [], []
    if grep.rc != 0:
        raise GitError(grep)
    prefix = f"{base}:"
    paths = sorted(p[len(prefix):] if p.startswith(prefix) else p
                   for p in grep.stdout.decode("utf-8", errors="surrogateescape").split("\0") if p)
    refs: list[Reference] = []
    unchecked: list[str] = []
    read: list[str] = []
    for path in paths:
        raw = git(repo, "show", f"{base}:{path}").stdout
        kind = _kind(path, raw)
        if kind is None:
            continue
        read.append(path)
        if kind == "py":
            _python(path, raw, refs, unchecked)
        else:
            _script(path, raw, refs)
    return refs, unchecked, read


def collect(git: Git, repo: Path, base: str) -> tuple[list[Reference], list[str]]:
    """References and "not checked" lines in the tracked files at BASE."""
    refs, unchecked, _ = _scan(git, repo, base)
    return refs, unchecked


def read_files(git: Git, repo: Path, base: str) -> list[str]:
    """The files G7 reads at BASE (part of the gate inputs)."""
    return _scan(git, repo, base)[2]


class _Index:
    """Modules under T's src/ and the names each binds at module level."""

    def __init__(self, tree: SourceTree) -> None:
        self.files: dict[str, str] = {}   # module -> path
        self.modules: set[str] = set()
        for path in tree.files:
            mod = module_name(path)
            if mod is None:
                continue
            self.files[mod] = path
            parts = mod.split(".")
            self.modules.update(".".join(parts[:i]) for i in range(1, len(parts) + 1))   # namespace packages too
        self.tree = tree
        self.cache: dict[str, set[str] | None] = {}

    def names(self, module: str, seen: frozenset[str] = frozenset()) -> set[str] | None:
        if module in self.cache:
            return self.cache[module]
        path = self.files.get(module)
        if path is None:
            return set()   # a namespace package binds no names of its own
        try:
            body = ast.parse(self.tree.files[path]).body
        except (SyntaxError, ValueError):
            self.cache[module] = None
            return None
        bound: set[str] = set()
        stars: list[tuple[str | None, int]] = []
        _bind(body, bound, stars)
        package = module if path.endswith("/__init__.py") else module.rpartition(".")[0]
        for target, level in stars:
            if level:
                parts = package.split(".")
                base = ".".join(parts[:len(parts) - (level - 1)]) if level - 1 < len(parts) else ""
                target = f"{base}.{target}" if target else base
            if target and target in self.files and target not in seen:
                bound |= self.names(target, seen | {module}) or set()
        self.cache[module] = bound
        return bound

    def has(self, module: str, name: str) -> bool | None:
        if f"{module}.{name}" in self.modules:
            return True   # a submodule
        names = self.names(module)
        return None if names is None else name in names


def _targets(node: ast.expr, out: set[str]) -> None:
    if isinstance(node, ast.Name):
        out.add(node.id)
    elif isinstance(node, (ast.Tuple, ast.List)):
        for elt in node.elts:
            _targets(elt, out)
    elif isinstance(node, ast.Starred):
        _targets(node.value, out)


def _bind(stmts: list[ast.stmt], out: set[str], stars: list[tuple[str | None, int]]) -> None:
    """Names bound by module-level statements, including those inside top-level if/try/with/for blocks."""
    for s in stmts:
        if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            out.add(s.name)
        elif isinstance(s, ast.Assign):
            for target in s.targets:
                _targets(target, out)
        elif isinstance(s, (ast.AnnAssign, ast.AugAssign)):
            _targets(s.target, out)
        elif isinstance(s, ast.Import):
            out.update(a.asname or a.name.split(".")[0] for a in s.names)
        elif isinstance(s, ast.ImportFrom):
            for a in s.names:
                if a.name == "*":
                    stars.append((s.module, s.level))
                else:
                    out.add(a.asname or a.name)
        elif _TYPE_ALIAS is not None and isinstance(s, _TYPE_ALIAS):
            _targets(s.name, out)   # type: ignore[attr-defined]
        elif isinstance(s, _BLOCKS):
            if isinstance(s, (ast.For, ast.AsyncFor)):
                _targets(s.target, out)
            for field in ("body", "orelse", "finalbody"):
                _bind(getattr(s, field, None) or [], out, stars)
            for handler in getattr(s, "handlers", None) or []:
                _bind(handler.body, out, stars)


def check(git: Git, repo: Path, mirror: Path, *, base: str, t: str) -> GateResult:
    """G7: missing modules or names FAIL; no reference at all is n/a; unreadable references are listed."""
    refs, unchecked = collect(git, repo, base)
    if not refs and not unchecked:
        return GateResult("G7", "n/a", "G7: no agent_ratchet reference at BASE", None, None, NO_LOG)
    index = _Index(load_tree(git, mirror, t)) if refs else None
    misses: list[str] = []
    for ref in refs:
        assert index is not None
        if ref.module not in index.modules:
            misses.append(f"{ref.origin}: module {ref.module} is missing at T")
        elif ref.name is not None:
            found = index.has(ref.module, ref.name)
            if found is None:
                misses.append(f"{ref.origin}: {ref.module} does not parse at T")
            elif not found:
                misses.append(f"{ref.origin}: {ref.module}.{ref.name} is not defined at T")
    tail = "".join(f"; {line}" for line in unchecked)
    if misses:
        return GateResult("G7", "FAIL", "G7: missing at T: " + "; ".join(misses) + tail, None, None, NO_LOG)
    return GateResult("G7", "PASS", f"G7: {len(refs)} references resolve at T" + tail, None, None, NO_LOG)
