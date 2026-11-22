"""Child-process environment policy and the lock-update refusal text."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Mapping, MutableMapping

from .exits import UsageError

AGENT_MARKERS = ("CLAUDECODE", "AI_AGENT", "CODEX_THREAD_ID", "CODEX_SHELL", "ANTIGRAVITY_AGENT")
STRIP_PREFIXES = ("GIT_", "GLOBAL_", "HUSKY", "SKIP", "PRE_COMMIT_", "LEFTHOOK", "ALLOW_")
STRIP_EXACT = ("GH_REPO", "VIRTUAL_ENV")
LOCK_UPDATE_ENV = "ALLOW_GUARD_LOCK_UPDATE"


def forbidden_env_key(key: str) -> bool:
    return key.startswith(STRIP_PREFIXES)


def take_lock_update_flag(environ: MutableMapping[str, str]) -> bool:
    """Pop the lock-update variable; only the exact value "1" counts."""
    return environ.pop(LOCK_UPDATE_ENV, None) == "1"


def agent_markers_present(environ: Mapping[str, str]) -> bool:
    return any(environ.get(m) for m in AGENT_MARKERS)


def _same_dir(entry: str, target: Path) -> bool:
    if not entry:
        return False
    try:
        return Path(os.path.realpath(entry)) == Path(os.path.realpath(target))
    except OSError:
        return False


def base_child_env(environ: Mapping[str, str], *, tool_bin: Path) -> dict[str, str]:
    out = {k: v for k, v in environ.items() if not forbidden_env_key(k) and k not in STRIP_EXACT}
    if "PATH" in out:
        out["PATH"] = os.pathsep.join(e for e in out["PATH"].split(os.pathsep) if not _same_dir(e, tool_bin))
    out["GIT_TERMINAL_PROMPT"] = "0"
    out["GH_PROMPT_DISABLED"] = "1"
    return out


def commit_env(base: Mapping[str, str], extra: Mapping[str, str], *, lock_update: bool) -> dict[str, str]:
    out = {**base, **extra}
    if lock_update:
        out[LOCK_UPDATE_ENV] = "1"
    allowed = {"GIT_TERMINAL_PROMPT"} | ({LOCK_UPDATE_ENV} if lock_update else set())
    for key in out:
        if forbidden_env_key(key) and key not in allowed:
            raise UsageError(f"environment variable {key} must not reach a commit")
    return out


def g6_env(base: Mapping[str, str], tmp: Path, *, uv_cache: Path) -> dict[str, str]:
    dirs = {
        "HOME": tmp / "home",
        "XDG_CONFIG_HOME": tmp / "xdg" / "config",
        "XDG_CACHE_HOME": tmp / "xdg" / "cache",
        "XDG_DATA_HOME": tmp / "xdg" / "data",
        "XDG_STATE_HOME": tmp / "xdg" / "state",
    }
    for d in dirs.values():
        d.mkdir(parents=True, exist_ok=True)
    out = dict(base)
    out.update({k: str(v) for k, v in dirs.items()})
    out.update({
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "UV_CACHE_DIR": str(uv_cache),
    })
    return out


def refusal_lines(command: str, *, markers: bool) -> list[str]:
    """How to tell the operator to run a command that needs the lock-update flag."""
    if markers:
        return [f"Run in your own terminal: {command}",
                f"It needs {LOCK_UPDATE_ENV}=1 set by you, not by an agent."]
    return [f"Run: {LOCK_UPDATE_ENV}=1 {command}"]
