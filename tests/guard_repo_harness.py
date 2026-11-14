"""agent-ratchet conformance harness: throwaway Git repositories exercised through `python -m agent_ratchet`."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"


def _git(cwd: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=True).stdout.strip()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json_bytes(payload: object) -> bytes:
    return (json.dumps(payload, indent=2) + "\n").encode("utf-8")


def _write_files(repo: Path, mapping: dict[str, str | bytes]) -> list[str]:
    for rel, content in mapping.items():
        p = repo / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            p.write_bytes(content)
        else:
            p.write_text(content, encoding="utf-8")
    return list(mapping.keys())


def _commit_files(repo: Path, msg: str, mapping: dict[str, str | bytes], include_guards: bool = False) -> str:
    rels = _write_files(repo, mapping)
    if include_guards:
        _git(repo, "add", "scripts/audit/audit_guard_config.json", *rels)
    else:
        _git(repo, "add", *rels)
    _git(repo, "commit", "-q", "-m", msg)
    return _git(repo, "rev-parse", "HEAD")


def _init_guard_repo(tmp_dir: str, guard_version: str | None = None) -> Path:
    repo = Path(tmp_dir)
    for args in (["init", "-q"], ["config", "core.hooksPath", "/dev/null"], ["config", "user.email", "guard@example.com"], ["config", "user.name", "Guard Test"]):
        _git(repo, *args)
    for d in ("scripts/audit", "src/domain", "tests/baselines"):
        (repo / d).mkdir(parents=True, exist_ok=True)
    (repo / "scripts" / "audit" / "audit_guard_config.json").write_bytes(_json_bytes({"extra_slop_rules": [], "legacy_loc_waivers": []}))
    return repo


def _run_tool(subcommand: str, repo: Path, *args: str, extra_env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, **(extra_env or {})}
    env["PYTHONPATH"] = os.pathsep.join(filter(None, [str(SRC_DIR), env.get("PYTHONPATH", "")]))
    if extra_env is None:
        env.pop("ALLOW_GUARD_LOCK_UPDATE", None)
    return subprocess.run([sys.executable, "-m", "agent_ratchet", subcommand, *args], cwd=repo, env=env, capture_output=True, text=True)


def _run_scanner(repo: Path, *args: str, extra_env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return _run_tool("scan", repo, *args, extra_env=extra_env)


def _run_baseline_guard(repo: Path, *args: str, extra_env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return _run_tool("baseline-integrity", repo, *args, extra_env=extra_env)
