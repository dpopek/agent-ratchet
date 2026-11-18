"""Package extras [php] / [magento]: declared pins and a real install smoke test."""

from __future__ import annotations

from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tomllib

import pytest

from agent_ratchet.profile import REQUIRED_MODULES

REPO_ROOT = Path(__file__).resolve().parent.parent

PARSE_CODE = """\
import tree_sitter, tree_sitter_php
parser = tree_sitter.Parser(tree_sitter.Language(tree_sitter_php.language_php()))
print(parser.parse(b"<?php echo 1;").root_node.has_error)
"""


def test_extras_declared_verbatim() -> None:
    project = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert project["dependencies"] == []
    assert project["optional-dependencies"] == {
        "php": ["tree-sitter==0.25.2", "tree-sitter-php==0.25.1"],
        "magento": ["agent-ratchet[php]", "defusedxml==0.7.1"],
    }


def _pypi_reachable() -> bool:
    try:
        socket.create_connection(("pypi.org", 443), timeout=3).close()
    except OSError:
        return False
    return True


@pytest.mark.integration
@pytest.mark.parametrize("extra", ["php", "magento"])
def test_extra_installs_and_parses(extra: str) -> None:
    if shutil.which("uv") is None:
        pytest.skip("uv is not installed")
    if sys.version_info >= (3, 15):
        pytest.skip("tree-sitter wheels are not published for 3.15 (best-effort sdist build)")
    if not _pypi_reachable():
        pytest.skip("PyPI is unreachable")
    imports = "".join(f"import {mod}\n" for mod in REQUIRED_MODULES[extra])
    result = subprocess.run(
        [
            "uv", "run", "--no-config", "--no-project", "--isolated", "--python", sys.executable,
            "--with", f"agent-ratchet[{extra}] @ {REPO_ROOT.as_uri()}",
            "--", "python", "-c", imports + PARSE_CODE,
        ],
        capture_output=True, text=True, timeout=600, check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip().splitlines()[-1] == "False"
