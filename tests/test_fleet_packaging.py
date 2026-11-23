"""Wheel contents: the main wheel stays `agent_ratchet` + `guard_core`; the fleet wheel is separate and ships its
confirmation helper source and its console script."""

from __future__ import annotations

import os
import subprocess
import zipfile
from pathlib import Path

from agent_ratchet.version import VERSION

ROOT = Path(__file__).resolve().parents[1]


def build_wheel(project: Path, out_dir: Path) -> Path:
    """`uv build --wheel --out-dir <out_dir>` with `project` as cwd; the build output stays under `out_dir`."""
    out_dir.mkdir(parents=True, exist_ok=True)
    env = {k: v for k, v in os.environ.items() if not k.startswith(("GIT_", "VIRTUAL_ENV"))}
    done = subprocess.run(
        ["uv", "build", "--wheel", "--out-dir", str(out_dir)], cwd=project, env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=300)
    assert done.returncode == 0, done.stdout[-3000:]
    wheels = sorted(out_dir.glob("*.whl"))
    assert len(wheels) == 1, wheels
    return wheels[0]


def wheel_names(wheel: Path) -> list[str]:
    with zipfile.ZipFile(wheel) as archive:
        return archive.namelist()


def test_main_wheel_file_list_unchanged(tmp_path):
    names = wheel_names(build_wheel(ROOT, tmp_path / "dist"))
    assert {n.split("/")[0] for n in names} == {"agent_ratchet", "guard_core", f"agent_ratchet-{VERSION}.dist-info"}
    assert not any(n.startswith(("guard_fleet", "fleet/", "tests/")) for n in names)


def test_fleet_wheel_ships_confirm_swift_and_script(tmp_path):
    wheel = build_wheel(ROOT / "fleet", tmp_path / "dist")
    names = wheel_names(wheel)
    assert "guard_fleet/confirm.swift" in names
    assert not any(n.startswith(("agent_ratchet/", "guard_core/", "tests/")) for n in names)
    entry_points = next(n for n in names if n.endswith(".dist-info/entry_points.txt"))
    with zipfile.ZipFile(wheel) as archive:
        text = archive.read(entry_points).decode("utf-8")
    assert "[console_scripts]" in text
    assert "guard-fleet = guard_fleet.cli:main" in text.splitlines()
