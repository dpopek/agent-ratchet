"""What a consumer's dev venv has installed, and what its main checkout's HEAD says it should have."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Mapping

from .config import Consumer
from .git import Git, show_bytes
from .lockfile import LockParseError, parse_lock
from .proc import Runner

_SCRIPT = (
    "import importlib.metadata as m, json\n"
    "try:\n"
    "    raw = m.distribution('agent-ratchet').read_text('direct_url.json')\n"
    "    commit = json.loads(raw)['vcs_info']['commit_id'] if raw else ''\n"
    "except Exception:\n"
    "    commit = ''\n"
    "print(commit)\n"
)
_SHA_RE = re.compile(r"[0-9a-f]{40}")
_PIN_RE = re.compile(r"agent-ratchet(?:\[[a-z,]+\])? @ git\+https://github\.com/dpopek/agent-ratchet@([0-9a-f]{40})")
_TIMEOUT = 30


def installed_commit(run: Runner, env: Mapping[str, str], venv: Path) -> str | None:
    """The commit agent-ratchet was installed from (PEP 610 `direct_url.json`); None when unknown."""
    try:
        r = run((str(venv / "bin" / "python"), "-I", "-c", _SCRIPT), cwd=venv.parent, env=env, timeout=_TIMEOUT)
    except OSError:
        return None   # no interpreter there
    out = r.text.strip()
    return out if r.rc == 0 and _SHA_RE.fullmatch(out) else None


def head_target(git: Git, repo: Path, consumer: Consumer) -> tuple[str | None, str | None, str]:
    """(pin spec as written at HEAD, extras bracket included; guard.lock SHA at HEAD; note)."""
    spec = pin_sha = None
    if consumer.pin_kind != "none" and consumer.pin_file:
        text = show_bytes(git, repo, "HEAD", consumer.pin_file)
        found = _PIN_RE.search(text.decode("utf-8", errors="replace")) if text is not None else None
        if found:
            spec, pin_sha = found.group(0), found.group(1)
    raw = show_bytes(git, repo, "HEAD", "guard.lock")
    lock_sha = None
    if raw is not None:
        try:
            lock_sha = parse_lock(raw).sha
        except LockParseError:
            return spec, None, "guard.lock unparseable at HEAD"
    if lock_sha is None:
        return spec, None, "no guard.lock at HEAD"
    if consumer.pin_kind != "none" and spec is None:
        return None, lock_sha, f"no agent-ratchet pin line in {consumer.pin_file} at HEAD"
    if pin_sha is not None and pin_sha != lock_sha:
        return spec, lock_sha, "pin and lock disagree at HEAD"
    return spec, lock_sha, ""
