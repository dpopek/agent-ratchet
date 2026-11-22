from __future__ import annotations

import ast
import sys
import tomllib
from pathlib import Path

from guard_fleet import cli

FLEET = Path(__file__).resolve().parents[1]
SRC = FLEET / "src"


def top_level_imports(path: Path) -> list[str]:
    mods: list[str] = []
    for node in ast.parse(path.read_text(encoding="utf-8")).body:
        if isinstance(node, ast.Import):
            mods.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            mods.append(node.module)
    return mods


def test_package_imports_only_stdlib() -> None:
    allowed = sys.stdlib_module_names | {"guard_fleet"}
    files = list(SRC.rglob("*.py"))
    assert files
    for path in files:
        for mod in top_level_imports(path):
            assert mod.split(".")[0] in allowed, (path, mod)


def test_pyproject_declares_script_and_package_data() -> None:
    data = tomllib.loads((FLEET / "pyproject.toml").read_text(encoding="utf-8"))
    assert data["project"]["scripts"] == {"guard-fleet": "guard_fleet.cli:main"}
    assert data["project"]["dependencies"] == []
    assert data["build-system"]["requires"] == ["hatchling==1.33.0"]
    assert (SRC / "guard_fleet" / "confirm.swift").is_file()


def test_main_without_arguments_is_usage_error() -> None:
    assert cli.main([]) == 2
