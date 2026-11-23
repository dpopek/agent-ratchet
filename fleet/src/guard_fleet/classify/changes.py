"""Changed paths of a release: metadata, version-only edits, or a surface level (spec §6.5 "Changed paths")."""

from __future__ import annotations

import ast
import tomllib
from dataclasses import dataclass

from .canonical import canonical, canonical_toml
from .gating import Level, bindings
from .surfaces import REGULAR_MODES, SurfaceMap
from .tree import SourceTree, module_name

METADATA_EXACT = ("CHANGELOG.md", "AGENTS.md", "LICENSE", "uv.lock")
METADATA_PREFIXES = ("docs/", "tests/", ".github/", "tools/", "fleet/")
IGNORE_FILES = frozenset({".gitignore", ".hgignore"})
PYPROJECT = "pyproject.toml"
VERSION_PY = "src/agent_ratchet/version.py"
VERSION_NAME = "VERSION"


@dataclass(frozen=True)
class ChangedPath:
    path: str
    status: str
    level: Level | None   # None = metadata (no surface)
    reason: str


def is_metadata(path: str) -> bool:
    return (path in METADATA_EXACT or path.startswith(METADATA_PREFIXES)
            or ("/" not in path and path.startswith("README")))


def version_only_pyproject(p: bytes | None, t: bytes | None) -> bool:
    """Both parse, and their type-tagged canonical forms are equal once `project.version` is dropped."""
    forms = [_toml_without_version(raw) for raw in (p, t)]
    return forms[0] is not None and forms[0] == forms[1]


def _toml_without_version(raw: bytes | None) -> object | None:
    if raw is None:
        return None
    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError):
        return None
    project = data.get("project")
    if isinstance(project, dict):
        project.pop("version", None)
    return canonical_toml(data)


def version_only_version_py(p: bytes | None, t: bytes | None) -> bool:
    """Both parse, each has exactly one module binding of VERSION in the accepted form, and their canonical ASTs
    are equal once that binding's value is replaced with `""`."""
    forms = [_module_without_version(raw) for raw in (p, t)]
    return forms[0] is not None and forms[0] == forms[1]


def _module_without_version(raw: bytes | None) -> object | None:
    if raw is None:
        return None
    try:
        module = ast.parse(raw)
        found = list(bindings(ast.walk(module), VERSION_NAME))
    except (SyntaxError, ValueError, RecursionError):
        return None
    shaped = [stmt for stmt in module.body if _is_version_binding(stmt)]
    if len(found) != 1 or len(shaped) != 1 or _target(shaped[0]) is not found[0]:
        return None
    shaped[0].value = ast.Constant("")
    try:
        return canonical(module)
    except RecursionError:
        return None


def _is_version_binding(stmt: ast.stmt) -> bool:
    """`VERSION: str = "<str>"` or `VERSION = "<str>"`."""
    if isinstance(stmt, ast.AnnAssign):
        ok = (isinstance(stmt.target, ast.Name) and stmt.target.id == VERSION_NAME and stmt.simple == 1
              and isinstance(stmt.annotation, ast.Name) and stmt.annotation.id == "str")
    elif isinstance(stmt, ast.Assign):
        ok = len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name) and stmt.targets[0].id == VERSION_NAME
    else:
        return False
    return ok and isinstance(stmt.value, ast.Constant) and type(stmt.value.value) is str


def _target(stmt: ast.stmt) -> ast.expr:
    return stmt.target if isinstance(stmt, ast.AnnAssign) else stmt.targets[0]


def classify_path(path: str, status: str, *, p_tree: SourceTree, t_tree: SourceTree,
                  p_map: SurfaceMap, t_map: SurfaceMap) -> ChangedPath:
    def core(reason: str) -> ChangedPath:
        return ChangedPath(path, status, Level.CORE, reason)

    if path.rpartition("/")[2] in IGNORE_FILES:
        return core("ignore file (decides the wheel's contents)")
    if is_metadata(path):
        return ChangedPath(path, status, None, "metadata")
    if path == PYPROJECT:
        if version_only_pyproject(p_tree.pyproject, t_tree.pyproject):
            return ChangedPath(path, status, None, "version-only")
        return core("pyproject.toml changed beyond project.version")
    if path.startswith("consumer/"):
        return core("consumer/**")
    if not path.startswith("src/"):
        return core("unknown path")
    if path.startswith("src/guard_core/"):
        return core("src/guard_core/**")
    for side, tree in (("P", p_tree), ("T", t_tree)):
        mode = tree.modes.get(path)
        if mode == "120000":
            return core(f"symlink under src/ at {side} (mode {mode})")
        if mode is not None and mode not in REGULAR_MODES:
            return core(f"non-regular entry under src/ at {side} (mode {mode})")
    if path == VERSION_PY:
        if version_only_version_py(p_tree.files.get(path), t_tree.files.get(path)):
            return ChangedPath(path, status, None, "version-only")
        return core("version.py changed beyond the VERSION value")
    name = module_name(path)
    if name is None:
        return core("non-.py file under src/" if not path.endswith(".py") else "not an importable module path")
    levels = {side: m.level_of[name] for side, m in (("P", p_map), ("T", t_map)) if name in m.level_of}
    if not levels:
        return core(f"module {name} is in neither tree")
    return ChangedPath(path, status, min(levels.values()),
                       f"module {name}: " + ", ".join(f"{lv.name.lower()} at {side}" for side, lv in levels.items()))
