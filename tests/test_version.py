from __future__ import annotations

import importlib.metadata
import json
import os
from pathlib import Path
import subprocess
import sys

from guard_core import version

SRC_DIR = Path(__file__).resolve().parent.parent / "src"


def _run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "PYTHONPATH": str(SRC_DIR)}
    return subprocess.run([sys.executable, "-m", "guard_core", *args], capture_output=True, text=True, env=env)


class _FakeDistribution:
    def __init__(self, payload: str | None) -> None:
        self._payload = payload

    def read_text(self, filename: str) -> str | None:
        return self._payload if filename == "direct_url.json" else None


def test_version_prints_semver() -> None:
    result = _run_cli("version")
    assert result.returncode == 0
    assert result.stdout == "3.0.1\n"
    assert version.GUARD_VERSION == "3.0.1"


def test_version_sha_without_vcs_metadata_exits_3(monkeypatch) -> None:
    monkeypatch.setattr(importlib.metadata, "distribution", lambda name: _FakeDistribution(None))
    assert version.installed_sha() is None


def test_version_sha_subprocess_without_vcs_metadata_exits_3() -> None:
    result = _run_cli("version", "--sha")
    assert result.returncode == 3
    assert "guard-core:" in result.stderr


def test_installed_sha_reads_direct_url(monkeypatch) -> None:
    payload = json.dumps({"url": "https://example.invalid/guard-core", "vcs_info": {"vcs": "git", "commit_id": "a" * 40}})
    monkeypatch.setattr(importlib.metadata, "distribution", lambda name: _FakeDistribution(payload))
    assert version.installed_sha() == "a" * 40


def test_installed_sha_none_for_non_vcs_install(monkeypatch) -> None:
    payload = json.dumps({"url": "file:///tmp/x", "dir_info": {"editable": True}})
    monkeypatch.setattr(importlib.metadata, "distribution", lambda name: _FakeDistribution(payload))
    assert version.installed_sha() is None


def test_installed_sha_none_when_package_missing(monkeypatch) -> None:
    def _raise(name: str) -> None:
        raise importlib.metadata.PackageNotFoundError(name)

    monkeypatch.setattr(importlib.metadata, "distribution", _raise)
    assert version.installed_sha() is None


def test_build_backend_is_pinned_exactly() -> None:
    import tomllib

    pyproject = tomllib.loads((SRC_DIR.parent / "pyproject.toml").read_text(encoding="utf-8"))
    requires = pyproject["build-system"]["requires"]
    assert len(requires) == 1 and requires[0].startswith("hatchling==")
    assert all(part.isdigit() for part in requires[0].removeprefix("hatchling==").split("."))


def test_pyproject_version_matches_guard_version() -> None:
    import tomllib

    pyproject = tomllib.loads((SRC_DIR.parent / "pyproject.toml").read_text(encoding="utf-8"))
    assert pyproject["project"]["version"] == version.GUARD_VERSION
