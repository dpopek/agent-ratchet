"""`guard-fleet venvs`: consumer dev-venv drift against the main checkout's HEAD pin, and an opt-in refresh.

Only local dev venvs change. The fleet never pulls, checks out or edits a consumer's checkout.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .config import Consumer, FleetConfig
from .deps import Deps
from .exits import FleetExit, UsageError
from .gh import Gh, GhError
from .git import Git, GitError, ls_remote, rev_parse
from .locks import RunLock
from .plan import _clients
from .proc import low_priority_prefix
from .venvinfo import head_target, installed_commit

State = Literal["ok", "drift", "disagree", "missing", "in-use", "refreshed", "failed"]

_PGREP_TIMEOUT = 10
_INSTALL_TIMEOUT = 600
_BLOCKING = frozenset({"in-use", "failed", "disagree", "missing"})
_HINT = "pull the main checkouts, then run guard-fleet venvs --refresh"


@dataclass(frozen=True)
class VenvRow:
    short: str
    venv: Path
    installed: str | None
    spec: str | None
    lock_sha: str | None
    behind: int | None
    state: State
    note: str


def drifted(rows: list[VenvRow] | tuple[VenvRow, ...]) -> bool:
    return any(r.state in ("drift", "disagree") for r in rows)


def _selected(cfg: FleetConfig, only: tuple[str, ...]) -> tuple[Consumer, ...]:
    for short in only:
        cfg.by_short(short)   # unknown short: UsageError before any lock or network work
    return tuple(c for c in cfg.consumers if c.venvs and (not only or c.short in only))


def _behind(git: Git, gh: Gh, consumer: Consumer) -> tuple[int | None, str]:
    """How many commits the live default head has that the checkout's HEAD lacks; (None, note) when unknown."""
    try:
        head = rev_parse(git, consumer.dir, "HEAD")
        ref = f"refs/heads/{consumer.default_branch}"
        d = ls_remote(git, consumer.dir, f"https://github.com/{consumer.slug}", ref).get(ref)
        if head is None or d is None:
            return None, f"behind origin unknown: {'no HEAD' if head is None else ref + ' not found on origin'}"
        if head == d:
            return 0, ""
        return int(gh.compare(consumer.slug, head, d)["ahead_by"]), ""
    except GhError as exc:
        return None, f"behind origin unknown: {exc.message}"
    except GitError as exc:
        return None, f"behind origin unknown: {exc}"


def _consumer_rows(deps: Deps, git: Git, gh: Gh, consumer: Consumer) -> list[VenvRow]:
    spec = lock_sha = None
    note = ""
    behind: int | None = None
    behind_note = ""
    if consumer.dir.is_dir():
        try:
            spec, lock_sha, note = head_target(git, consumer.dir, consumer)
        except GitError as exc:
            note = f"HEAD unreadable: {exc}"
        behind, behind_note = _behind(git, gh, consumer)
    rows: list[VenvRow] = []
    for venv in consumer.venvs:
        notes: list[str] = []
        installed = None
        if not consumer.dir.is_dir():
            state: State = "missing"
            notes.append(f"checkout {consumer.dir} is absent")
        elif not (venv / "bin" / "python").exists():
            state = "missing"
            notes.append("no interpreter in the venv")
        else:
            installed = installed_commit(deps.run, git.env, venv)
            if note:
                state = "disagree"
                notes.append(note)
            else:
                state = "ok" if installed is not None and installed == lock_sha else "drift"
        if behind:
            notes.append(f"behind origin by {behind}; pull, then rerun")
        if behind_note:
            notes.append(behind_note)
        rows.append(VenvRow(consumer.short, venv, installed, spec, lock_sha, behind, state, "; ".join(notes)))
    return rows


def report(deps: Deps, git: Git, gh: Gh, cfg: FleetConfig, *, only: tuple[str, ...]) -> list[VenvRow]:
    consumers = _selected(cfg, only)
    lock = RunLock(deps.dirs.run_lock)
    lock_free = not lock.acquire(exclusive=False)
    try:
        rows = [row for c in consumers for row in _consumer_rows(deps, git, gh, c)]
    finally:
        lock.release()
    if lock_free:
        rows = [dataclasses.replace(r, note="; ".join(filter(None, (r.note, "run lock busy: reported without it"))))
                for r in rows]
    return rows


def _refresh_row(deps: Deps, git: Git, row: VenvRow) -> VenvRow:
    venv = row.venv
    if row.spec is None:
        return dataclasses.replace(row, state="failed", note="; ".join(filter(None, (row.note, "no pin spec at HEAD to install"))))
    busy = deps.run(("pgrep", "-f", f"{venv}/bin/"), cwd=venv, env=git.env, timeout=_PGREP_TIMEOUT).rc
    if busy != 1:   # 0 = a process uses it; anything else is unknown, so fail closed
        return dataclasses.replace(row, state="in-use", note="; ".join(filter(None, (row.note, "venv in use; skipped"))))
    argv = low_priority_prefix() + ("uv", "pip", "install", "--python", f"{venv}/bin/python", "--no-config", row.spec)
    result = deps.run(argv, cwd=venv, env=git.env, timeout=_INSTALL_TIMEOUT)
    got = installed_commit(deps.run, git.env, venv)
    if result.rc == 0 and got is not None and got == row.lock_sha:
        return dataclasses.replace(row, installed=got, state="refreshed")
    why = (f"install failed (rc={result.rc}): {result.stderr.decode('utf-8', errors='replace').strip()[-300:]}"
           if result.rc != 0 else f"installed commit {got or 'unknown'} is not the lock sha after install")
    return dataclasses.replace(row, installed=got, state="failed", note="; ".join(filter(None, (row.note, why))))


def refresh(deps: Deps, git: Git, gh: Gh, cfg: FleetConfig, *, only: tuple[str, ...]) -> list[VenvRow]:
    consumers = _selected(cfg, only)
    lock = RunLock(deps.dirs.run_lock)
    if not lock.acquire(exclusive=True):
        raise UsageError(f"lock busy: {deps.dirs.run_lock}")
    try:
        rows = [row for c in consumers for row in _consumer_rows(deps, git, gh, c)]
        return [_refresh_row(deps, git, r) if r.state == "drift" else r for r in rows]
    finally:
        lock.release()


_refresh = refresh   # run_venvs's `refresh` flag shadows the function


def run_venvs(deps: Deps, cfg: FleetConfig, *, refresh: bool, only: tuple[str, ...]) -> FleetExit:
    git, gh = _clients(deps)
    rows = (_refresh if refresh else report)(deps, git, gh, cfg, only=only)
    for r in rows:
        line = (f"{r.short}  {r.venv}  {r.state}  installed {r.installed[:12] if r.installed else 'unknown'}"
                f"  lock {r.lock_sha[:12] if r.lock_sha else 'unknown'}")
        deps.out.write(line + (f"  {r.note}" if r.note else "") + "\n")
    if drifted(rows):
        deps.out.write(_HINT + "\n")
    if refresh and any(r.state in _BLOCKING for r in rows):
        return FleetExit.BLOCKED
    return FleetExit.OK
