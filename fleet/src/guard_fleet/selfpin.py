"""guard-fleet self-pin: validate a tag like a target and rewrite self.lock atomically."""

from __future__ import annotations

import os
import tempfile

from . import confirm, env
from .deps import Deps
from .exits import FleetExit, UsageError
from .git import Git
from .locks import RunLock
from .mirror import refresh_mirror
from .target import validate_target


def run_self_pin(deps: Deps, git: Git, tag: str) -> FleetExit:
    lock = RunLock(deps.dirs.run_lock)
    if not lock.acquire(exclusive=True):
        raise UsageError(f"lock busy: another guard-fleet run holds {deps.dirs.run_lock}")
    try:
        target = validate_target(git, refresh_mirror(deps, git), tag)
        try:
            current = deps.dirs.self_lock.read_text(encoding="utf-8").strip() or "missing"
        except OSError:
            current = "missing"
        table = f"self.lock: {current}\nnew pin:   {target.tag} {target.sha}\n"
        reason = confirm.reason_text("self-pin", target.tag, target.sha, {},
                                     markers=env.agent_markers_present(deps.environ))
        confirm.ask(deps, table, reason)
        config_dir = deps.dirs.config_dir
        config_dir.mkdir(parents=True, exist_ok=True)
        tmp = tempfile.NamedTemporaryFile(dir=config_dir, delete=False)
        try:
            with tmp:
                tmp.write((target.sha + "\n").encode("ascii"))
                tmp.flush()
                os.fsync(tmp.fileno())
            os.chmod(tmp.name, 0o644)
            os.replace(tmp.name, deps.dirs.self_lock)
        except BaseException:
            try:
                os.unlink(tmp.name)
            except FileNotFoundError:
                pass
            raise
        return FleetExit.OK
    finally:
        lock.release()
