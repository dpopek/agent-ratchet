"""R10: an operator-owned guard config outside the scanned repository (local-only operation).

The override replaces the in-repo ``audit_guard_config.json`` for BASE and TARGET alike. It is set once by the
CLI entry point (``activate_cli``) and consulted by ``git_guard_io`` and ``lock_policy``.
"""

from __future__ import annotations

import copy
import os
from pathlib import Path
import subprocess
import sys
from typing import Any

from agent_ratchet.ast_safety import GuardAnalysisError

ENV_VAR = "AGENT_RATCHET_CONFIG"
_UNSAFE_MODE = 0o022
_state: dict[str, Any] = {"override": None, "noted": False}


def set_override(cfg: dict[str, Any] | None) -> None:
    """Install (or clear) the process-wide override; clearing also re-arms the one-time stderr note."""
    _state["override"] = cfg
    if cfg is None:
        _state["noted"] = False


def active_override() -> dict[str, Any] | None:
    cfg = _state["override"]
    return None if cfg is None else copy.deepcopy(cfg)


def override_active() -> bool:
    return _state["override"] is not None


def _repo_top_level(cwd: str | None) -> Path:
    proc = subprocess.run(["git", "rev-parse", "--show-toplevel"], cwd=cwd, capture_output=True, text=True, check=False)
    top = proc.stdout.strip() if proc.returncode == 0 else ""
    return Path(top or cwd or ".").resolve()


def resolve_external_config(cli_value: str | None, repo_root: Path) -> Path | None:
    """The validated external config path: the option wins over ``AGENT_RATCHET_CONFIG``; an empty env value is unset."""
    raw = cli_value if cli_value is not None else (os.environ.get(ENV_VAR) or None)
    if raw is None:
        return None
    if not raw.strip():
        raise GuardAnalysisError("--config-file needs a non-empty path")
    try:
        path = Path(raw).expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise GuardAnalysisError(f"External config {raw!r} is unreadable or missing: {exc}") from exc
    root = repo_root.resolve()
    if path == root or root in path.parents:
        raise GuardAnalysisError(f"External config {path} must lie outside the repository {root}")
    if not path.is_file():
        raise GuardAnalysisError(f"External config {path} is not a regular file")
    if os.name != "nt" and path.stat().st_mode & _UNSAFE_MODE:
        raise GuardAnalysisError(f"External config {path} must not be writable by group or others (chmod go-w)")
    return path


def load_external_config(path: Path) -> dict[str, Any]:
    """Parse with the same schema, defaults and validation as the in-repo ``audit_guard_config.json``."""
    from agent_ratchet.git_guard_io import parse_guard_config_bytes

    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise GuardAnalysisError(f"Cannot read external config {path}: {exc}") from exc
    return parse_guard_config_bytes(raw, str(path))


def activate_cli(cli_value: str | None, cwd: str | None = None) -> int | None:
    """CLI entry hook: install the override and print the note once. Returns exit code 2 on error, else None."""
    try:
        path = resolve_external_config(cli_value, _repo_top_level(cwd))
        if path is None:
            return None
        set_override(load_external_config(path))
    except GuardAnalysisError as exc:
        print(f"ERROR: [guard_analysis_error] {exc}", file=sys.stderr)
        return 2
    if not _state["noted"]:
        _state["noted"] = True
        print(f"note: using external config {path}", file=sys.stderr)
    return None
