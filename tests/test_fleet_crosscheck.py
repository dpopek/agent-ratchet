"""Cross-check of the fleet classifier against the real CLI: on a core-only config, a run over PHP and Magento
changes must not import any module the classifier calls a php or magento surface."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from fleet_import import guard_fleet, load_tree_from_worktree

guard_fleet()

from guard_fleet.classify.canonical import digest  # noqa: E402
from guard_fleet.classify.gating import Level  # noqa: E402
from guard_fleet.classify.surfaces import SurfaceMap, compute_surfaces  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
CONFIG_REL = "scripts/audit/audit_guard_config.json"

# Runs `agent_ratchet.cli.main(argv)` with the transition counters installed first, then prints one JSON line.
#   transitions: calls of `transition_scan._evaluate_transition`, the function that evaluates one commit pair.
#   gate_calls:  calls of the php/magento entry points `_evaluate_transition` ends with (their profile gates).
RUNNER = r"""
import contextlib, io, json, sys
import agent_ratchet.cli as cli
import agent_ratchet.transition_scan as ts

counts = {"transitions": 0, "gate_calls": 0}

def counted(name, key):
    original = getattr(ts, name)
    def wrapper(*args, **kwargs):
        counts[key] += 1
        return original(*args, **kwargs)
    setattr(ts, name, wrapper)

counted("_evaluate_transition", "transitions")
counted("php_transition_violations", "gate_calls")
counted("magento_transition_violations", "gate_calls")
sink = io.StringIO()
with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
    rc = cli.main(json.loads(sys.argv[1]))
print(json.dumps({"rc": rc, "modules": sorted(sys.modules), **counts}))
"""


def _env(home: Path) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("GIT_", "AGENT_RATCHET", "ALLOW_", "PRE_COMMIT", "HUSKY", "SKIP"))}
    env["HOME"] = str(home)
    return env


def _git(repo: Path, home: Path, *args: str) -> str:
    done = subprocess.run(
        ["git", "-c", "user.name=Fleet Test", "-c", "user.email=test@example.com", "-c", "commit.gpgsign=false",
         "-c", "core.hooksPath=/dev/null", "-c", "maintenance.auto=false", "-c", "gc.auto=0", "-C", str(repo), *args],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=_env(home), text=True, check=True, timeout=60)
    return done.stdout.strip()


def php_magento_fixture(tmp_path: Path) -> tuple[Path, Path, str]:
    """A repo whose history adds and edits .php, registration.php and etc/di.xml under a core-only config.

    Returns (repo, home, base sha); the range `<base>..HEAD` holds two commits.
    """
    home = tmp_path / "home"
    home.mkdir()
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, home, "init", "-q", "-b", "main")

    def write(rel: str, text: str) -> None:
        target = repo / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")

    module = "app/code/Alpha/Beta"
    write(CONFIG_REL, json.dumps({"languages": [], "frameworks": []}) + "\n")
    write("README.md", "alpha\n")
    _git(repo, home, "add", "--", CONFIG_REL, "README.md")
    _git(repo, home, "commit", "-q", "-m", "base")
    base = _git(repo, home, "rev-parse", "HEAD")

    write(f"{module}/registration.php", "<?php\nuse Magento\\Framework\\Component\\ComponentRegistrar;\n"
          "ComponentRegistrar::register(ComponentRegistrar::MODULE, 'Alpha_Beta', __DIR__);\n")
    write(f"{module}/Model/Thing.php", "<?php\nnamespace Alpha\\Beta\\Model;\n\nclass Thing\n{\n"
          "    public function run(): int\n    {\n        return 1;\n    }\n}\n")
    write(f"{module}/etc/di.xml", '<?xml version="1.0"?>\n<config>\n'
          '    <preference for="Alpha\\Beta\\Api\\ThingInterface" type="Alpha\\Beta\\Model\\Thing"/>\n</config>\n')
    _git(repo, home, "add", "--", module)
    _git(repo, home, "commit", "-q", "-m", "add php and di")

    write(f"{module}/Model/Thing.php", "<?php\nnamespace Alpha\\Beta\\Model;\n\nclass Thing\n{\n"
          "    public function run(): int\n    {\n        return 2;\n    }\n}\n")
    write(f"{module}/etc/di.xml", '<?xml version="1.0"?>\n<config>\n'
          '    <preference for="Alpha\\Beta\\Api\\ThingInterface" type="Alpha\\Beta\\Model\\Other"/>\n</config>\n')
    _git(repo, home, "add", "--", module)
    _git(repo, home, "commit", "-q", "-m", "edit php and di")
    return repo, home, base


def run_cli_in_subprocess(repo: Path, home: Path, argv: list[str]) -> dict:
    done = subprocess.run(
        [sys.executable, "-I", "-c", RUNNER, json.dumps(argv)], cwd=repo, env=_env(home),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=120)
    assert done.returncode == 0, done.stderr[-2000:]
    return json.loads(done.stdout.strip().splitlines()[-1])


def surface_modules(surfaces: SurfaceMap) -> set[str]:
    return {name for name, level in surfaces.level_of.items() if level is not Level.CORE}


def digest_of(surfaces: SurfaceMap) -> str:
    return digest((surfaces.all_core_reason, tuple(sorted((m, int(lv)) for m, lv in surfaces.level_of.items())),
                   tuple((g.module, g.func, g.kind, int(g.level), g.lineno) for g in surfaces.gates)))


# (argv, minimum `_evaluate_transition` calls). At this commit only the commit-range scan evaluates transitions:
# a plain `scan` reads worktree files and `baseline-integrity` never calls the transition scan, so both expect 0.
FORMS = [
    pytest.param(["scan"], 0, id="scan-worktree"),
    pytest.param(["scan", "--commit-range", "{base}..HEAD"], 2, id="scan-commit-range"),
    pytest.param(["baseline-integrity", "--require-base-ref", "--enforce-policy-isolation",
                  "--commit-range", "{base}..HEAD"], 0, id="baseline-integrity-range"),
]


@pytest.mark.parametrize("form,min_transitions", FORMS)
def test_core_only_run_loads_no_surface_module(tmp_path, form, min_transitions):
    """Transition count path: the brief's fallback is not needed for the range form, which hits a stable hook
    (`transition_scan._evaluate_transition`, counted by a wrapper installed before `main`). The other two forms
    never evaluate transitions, so for them the count is asserted to be exactly what the code does (0) and the
    test still proves the import claim for a run that loaded the whole CLI."""
    repo, home, base = php_magento_fixture(tmp_path)
    out = run_cli_in_subprocess(repo, home, [a.format(base=base) for a in form])
    surface = surface_modules(compute_surfaces(load_tree_from_worktree(ROOT)))
    assert surface, "the classifier found no php or magento surface module"
    assert out["transitions"] >= min_transitions
    if min_transitions:
        assert out["gate_calls"] >= 2 * min_transitions   # php and magento entry per evaluated transition
    assert "agent_ratchet.cli" in out["modules"]
    assert not (set(out["modules"]) & surface), sorted(set(out["modules"]) & surface)


def test_consumer_test_imports_load_no_surface_module(tmp_path):
    code = ("import json, sys\nimport agent_ratchet.baseline_diff, agent_ratchet.lock_policy, agent_ratchet.version\n"
            "print(json.dumps(sorted(sys.modules)))")
    done = subprocess.run([sys.executable, "-I", "-c", code], cwd=tmp_path, env=_env(tmp_path),
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=120)
    assert done.returncode == 0, done.stderr[-2000:]
    loaded = set(json.loads(done.stdout))
    surface = surface_modules(compute_surfaces(load_tree_from_worktree(ROOT)))
    assert {"agent_ratchet.baseline_diff", "agent_ratchet.lock_policy", "agent_ratchet.version"} <= loaded
    assert not (loaded & surface), sorted(loaded & surface)


def test_crosscheck_records_classifier_digest(record_property):
    surfaces = compute_surfaces(load_tree_from_worktree(ROOT))
    assert surfaces.all_core_reason is None
    value = digest_of(surfaces)
    assert len(value) == 64
    record_property("classifier_digest", value)
