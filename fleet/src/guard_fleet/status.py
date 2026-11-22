"""The read-only `status`: where each consumer stands against the newest v4 tag, plus what earlier rounds left behind."""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .config import Consumer, FleetConfig
from .deps import Deps
from .gh import Gh, GhError
from .git import Git, GitError, ls_remote, rev_parse
from .lockfile import LockParseError, parse_lock
from .locks import RunLock
from .mirror import mirror_readonly, refresh_mirror
from .names import is_fleet_worktree, parse_fleet_branch
from .plan import Planner, PlanRow, _clients
from .target import Target, newest_v4_tag, release_tag_for
from .venvinfo import head_target, installed_commit

_BRANCH_GLOB = "refs/heads/chore/agent-ratchet-*"
_LOCK_NAMES = ("index.lock", "HEAD.lock", "packed-refs.lock")


@dataclass(frozen=True)
class StatusRow:
    short: str
    pin_tag: str | None
    extras: str
    exposure_level: str
    latest_tag: str
    relation: Literal["CURRENT", "BEHIND", "EXPOSED-BEHIND", "BLOCKED"]
    open_fleet_prs: tuple[str, ...]
    leftovers: tuple[str, ...]
    stale_locks: tuple[str, ...]
    venv_lines: tuple[str, ...]
    note: str = ""   # why a row is BLOCKED, or which lookup failed


@dataclass(frozen=True)
class StatusReport:
    rows: tuple[StatusRow, ...]
    latest: Target
    mirror_note: str | None
    self_pin: str | None   # the tag self.lock pins ("malformed", or a short sha when untagged); None when absent


def _relation(row: PlanRow) -> Literal["CURRENT", "BEHIND", "EXPOSED-BEHIND", "BLOCKED"]:
    if row.decision == "CURRENT":
        return "CURRENT"
    if row.decision == "BLOCKED":
        return "BLOCKED"
    return "EXPOSED-BEHIND" if row.decision == "BUMP" else "BEHIND"   # plan ran with include_unexposed=False


def _worktree_records(git: Git, repo: Path) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for field in git(repo, "worktree", "list", "--porcelain", "-z").stdout.decode("utf-8", "surrogateescape").split("\0"):
        if field == "":
            if current:
                records.append(current)
                current = {}
            continue
        key, _, value = field.partition(" ")
        current[key] = value
    if current:
        records.append(current)
    return records


def _leftovers(git: Git, cfg: FleetConfig, consumer: Consumer, remote_url: str) -> tuple[str, ...]:
    resolved = dataclasses.replace(cfg, worktree_root=cfg.worktree_root.resolve())   # git prints real paths
    out: list[str] = []
    for rec in _worktree_records(git, consumer.dir):
        path = Path(rec.get("worktree", ""))
        branch = rec.get("branch", "").removeprefix("refs/heads/") or None
        if not (is_fleet_worktree(cfg, consumer, path, branch) or is_fleet_worktree(resolved, consumer, path, branch)):
            continue
        line = f"worktree {path} ({branch})"
        if "locked" in rec:
            line += " initializing" if rec["locked"] == "initializing" else f" locked: {rec['locked']}"
        out.append(line)
    refs = git(consumer.dir, "for-each-ref", "--format=%(refname)", _BRANCH_GLOB).text.splitlines()
    out += sorted(f"branch {n}" for n in (r.removeprefix("refs/heads/") for r in refs) if parse_fleet_branch(n))
    remote = ls_remote(git, consumer.dir, remote_url, _BRANCH_GLOB)
    out += sorted(f"remote {n}" for n in (r.removeprefix("refs/heads/") for r in remote) if parse_fleet_branch(n))
    return tuple(out)


def _stale_locks(git: Git, deps: Deps, consumer: Consumer) -> tuple[str, ...]:
    gitdir = Path(git(consumer.dir, "rev-parse", "--absolute-git-dir").text.strip())
    roots = [gitdir, *sorted(p for p in (gitdir / "worktrees").glob("*") if p.is_dir())]
    found: list[Path] = []
    for root in roots:
        found += [root / n for n in _LOCK_NAMES if (root / n).is_file()]
        found += sorted(p for p in (root / "refs").rglob("*.lock") if p.is_file())
    now = deps.clock.wall()
    return tuple(f"{p.relative_to(gitdir).as_posix()} ({max(0, round((now - p.stat().st_mtime) / 60))} min)"
                 for p in found)


def _venv_lines(deps: Deps, git: Git, gh: Gh, consumer: Consumer, d: str | None, env: dict[str, str],
                *, ask_gh: bool) -> tuple[str, ...]:
    if not consumer.venvs:
        return ()
    _spec, lock_sha, note = head_target(git, consumer.dir, consumer)
    behind = ""
    head = rev_parse(git, consumer.dir, "HEAD")
    if d and head and head != d and ask_gh:
        try:
            ahead_by = int(gh.compare(consumer.slug, head, d)["ahead_by"])
            behind = f"behind origin by {ahead_by}" if ahead_by else ""
        except GhError as exc:
            behind = f"behind origin unknown: {exc.message}"
    lines: list[str] = []
    for venv in consumer.venvs:
        got = installed_commit(deps.run, env, venv)
        line = (f"venv {venv}: installed {got[:8] if got else 'unknown'} vs HEAD lock "
                f"{lock_sha[:8] if lock_sha else 'unknown'}")
        lines.append(line + (f" ({note})" if note else ""))
        if behind:
            lines.append(f"venv {venv}: {behind}")
    return tuple(lines)


def _consumer_row(deps: Deps, cfg: FleetConfig, planner: Planner, consumer: Consumer, target: Target,
                  env: dict[str, str]) -> StatusRow:
    plan = planner.plan_consumer(consumer, target, include_unexposed=False)
    notes: list[str] = [plan.reason] if plan.decision == "BLOCKED" else []
    prs: tuple[str, ...] = ()
    leftovers: tuple[str, ...] = ()
    stale: tuple[str, ...] = ()
    venvs: tuple[str, ...] = ()
    git, gh = planner.git, planner.gh

    def lookup(what: str, fn):
        try:
            return fn()
        except (GitError, GhError) as exc:
            notes.append(f"{what} unknown: {getattr(exc, 'message', exc)}")
            return ()

    if not planner.gh_stopped:
        prs = lookup("open PRs", lambda: tuple(
            f"#{p['number']} {p['headRefName']}" for p in gh.pr_list_open(consumer.slug, base=consumer.default_branch)
            if parse_fleet_branch(str(p.get("headRefName", "")))))
    if consumer.dir.is_dir():
        leftovers = lookup("leftovers", lambda: _leftovers(git, cfg, consumer, planner.remote_url(consumer)))
        stale = lookup("stale locks", lambda: _stale_locks(git, deps, consumer))
        venvs = lookup("venvs", lambda: _venv_lines(deps, git, gh, consumer, plan.d, env,
                                                    ask_gh=not planner.gh_stopped))
    return StatusRow(
        consumer.short, plan.pin_tag, plan.extras or "-",
        plan.exposure.level.name.lower() if plan.exposure is not None else "-", target.tag, _relation(plan),
        prs, leftovers, stale, venvs, "; ".join(notes))


def _self_pin(deps: Deps, git: Git, mirror: Path) -> str | None:
    try:
        raw = deps.dirs.self_lock.read_bytes()
    except OSError:
        return None
    try:
        sha = parse_lock(raw).sha
    except LockParseError:
        return "malformed"
    return release_tag_for(git, mirror, sha) or sha[:12]


def collect_status(deps: Deps, cfg: FleetConfig) -> StatusReport:
    git, gh = _clients(deps)
    lock = RunLock(deps.dirs.run_lock)
    lock_free = not lock.acquire(exclusive=False)
    try:
        if lock_free:
            mirror, stamp = mirror_readonly(deps)
            note: str | None = f"mirror as of {stamp}"
        else:
            mirror, note = refresh_mirror(deps, git), None
        latest = newest_v4_tag(git, mirror)
        planner = Planner(deps, git, gh, mirror, lock_free=lock_free)
        rows = tuple(_consumer_row(deps, cfg, planner, c, latest, git.env) for c in cfg.consumers)
        self_pin = _self_pin(deps, git, mirror)
    finally:
        lock.release()
    return StatusReport(rows, latest, note, self_pin)


def render_status(report: StatusReport) -> str:
    lines = [f"Latest v4 tag: {report.latest.tag} ({report.latest.sha[:12]})"]
    if report.mirror_note:
        lines.append(report.mirror_note)
    lines.append(f"Fleet: self.lock pin: {report.self_pin or 'none'}; newest v4 tag: {report.latest.tag}")
    for r in report.rows:
        lines.append("")
        lines.append(f"{r.short}  pin {r.pin_tag or '-'} ({r.extras})  exposure {r.exposure_level}  "
                     f"latest {r.latest_tag}  {r.relation}")
        if r.note:
            lines.append(f"  note: {r.note}")
        for label, items in (("open fleet PR", r.open_fleet_prs), ("leftover", r.leftovers),
                             ("stale lock", r.stale_locks), ("", r.venv_lines)):
            lines += [f"  {label + ': ' if label else ''}{item}" for item in items]
    return "\n".join(lines) + "\n"


def run_status(deps: Deps, cfg: FleetConfig) -> int:
    deps.out.write(render_status(collect_status(deps, cfg)))
    return 0
