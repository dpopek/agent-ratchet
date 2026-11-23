"""Cleanup of fleet leftovers (spec 6.9): remove a fleet worktree or branch only when it is provably safe.

Safe means merged into the default branch, or carrying nothing but the fleet's own bump with no open PR. Every doubt
(an unreadable ref, a dirty worktree, a refused push, a git error) keeps the item and is reported.
"""

from __future__ import annotations

import dataclasses
import os
from dataclasses import dataclass
from pathlib import Path

from .config import Consumer, FleetConfig
from .confirm import ask, reason_simple
from .deps import Deps
from .env import agent_markers_present
from .exits import FleetExit, UsageError
from .gh import Gh
from .git import (Git, GitError, GitNetworkError, fetch_default, has_commit, is_ancestor, ls_remote, rev_parse,
                  show_bytes)
from .ledger import prune_tag_dirs
from .lockfile import LockParseError, parse_lock
from .locks import RunLock
from .mirror import refresh_mirror
from .names import is_fleet_worktree, parse_fleet_branch
from .plan import Planner, _clients
from .shape import check as shape_check
from .status import _worktree_records
from .target import check_tag_syntax

IGNORED_ALLOWLIST = (".pytest_cache", "__pycache__", ".mypy_cache", ".ruff_cache")
IGNORED_ALLOWLIST_SET = frozenset(IGNORED_ALLOWLIST)
_BRANCH_GLOB = "refs/heads/chore/agent-ratchet-*"
LOCK = "guard.lock"


@dataclass(frozen=True)
class CleanupContext:
    deps: Deps
    git: Git
    gh: Gh
    mirror: Path
    cfg: FleetConfig


@dataclass(frozen=True)
class Item:
    consumer: Consumer
    branch: str
    version: str
    worktree: Path | None
    local_head: str | None
    remote_head: str | None
    evidence: tuple[str, ...]
    safe: bool
    reason: str


def safety(git: Git, repo: Path, mirror: Path, consumer: Consumer, sha: str, d: str,
           open_pr: bool) -> tuple[bool, str]:
    """(safe, why). A git failure while proving ancestry raises GitError: the caller keeps the item."""
    if is_ancestor(git, repo, sha, d):
        return True, f"merged into {d[:8]}"
    base = git(repo, "merge-base", sha, d).text.strip()
    specs = []
    for label, rev in (("base", base), ("branch", sha)):
        raw = show_bytes(git, repo, rev, LOCK)
        if raw is None:
            return False, f"{LOCK} is missing at the {label} ({rev[:8]})"
        try:
            specs.append(parse_lock(raw))
        except LockParseError:
            return False, f"{LOCK} at the {label} ({rev[:8]}) is malformed"
    p, t = specs
    result = shape_check(git, repo, mirror, consumer, base=base, head=sha, p=p.sha, t=t.sha, extras=p.extras)
    if result.verdict != "PASS":
        return False, f"not only the fleet's content: {result.reason}"
    if open_pr:
        return False, f"fleet content only, but an open PR into {consumer.default_branch} exists"
    return True, "fleet content only"


def _planner(ctx: CleanupContext) -> Planner:
    return Planner(ctx.deps, ctx.git, ctx.gh, ctx.mirror, lock_free=True)


def _worktrees(ctx: CleanupContext, consumer: Consumer) -> tuple[dict[str, Path], set[str]]:
    """(fleet worktrees by branch, fleet-named branches checked out somewhere that is not the fleet's worktree)."""
    resolved = dataclasses.replace(ctx.cfg, worktree_root=ctx.cfg.worktree_root.resolve())   # git prints real paths
    fleet: dict[str, Path] = {}
    foreign: set[str] = set()
    for rec in _worktree_records(ctx.git, consumer.dir):
        branch = rec.get("branch", "").removeprefix("refs/heads/")
        if not branch or parse_fleet_branch(branch) is None:
            continue
        path = Path(rec.get("worktree", ""))
        if is_fleet_worktree(ctx.cfg, consumer, path, branch) or is_fleet_worktree(resolved, consumer, path, branch):
            fleet[branch] = path
        else:
            foreign.add(branch)
    return fleet, foreign


def _local_branches(ctx: CleanupContext, consumer: Consumer) -> dict[str, str]:
    out = ctx.git(consumer.dir, "for-each-ref", "--format=%(objectname) %(refname)", _BRANCH_GLOB).text
    found: dict[str, str] = {}
    for line in out.splitlines():
        sha, _, ref = line.partition(" ")
        name = ref.removeprefix("refs/heads/")
        if sha and parse_fleet_branch(name) is not None:
            found[name] = sha
    return found


def _remote_branches(ctx: CleanupContext, consumer: Consumer) -> dict[str, str]:
    refs = ls_remote(ctx.git, consumer.dir, _planner(ctx).remote_url(consumer), _BRANCH_GLOB)
    return {name.removeprefix("refs/heads/"): sha for name, sha in refs.items()
            if parse_fleet_branch(name.removeprefix("refs/heads/")) is not None}


def _default_head(ctx: CleanupContext, consumer: Consumer) -> str:
    """The default branch's head on origin, fetched object-only into the consumer's clone."""
    ref = f"refs/heads/{consumer.default_branch}"
    d = ls_remote(ctx.git, consumer.dir, _planner(ctx).remote_url(consumer), ref).get(ref)
    if d is None:
        raise UsageError(f"{consumer.short}: origin has no {consumer.default_branch}")
    fetch_default(ctx.git, consumer.dir, consumer.default_branch)
    return d


def _ensure_commit(ctx: CleanupContext, consumer: Consumer, sha: str, branch: str) -> None:
    if not has_commit(ctx.git, consumer.dir, sha):   # a remote-only branch: bring its objects in, refs untouched
        ctx.git.retrying(consumer.dir, "fetch", "--no-tags", "--no-write-fetch-head", "--refmap=", "origin",
                         f"refs/heads/{branch}")


def _judge(ctx: CleanupContext, consumer: Consumer, branch: str, d: str, local: str | None,
           remote: str | None) -> tuple[bool, str, tuple[str, ...]]:
    shas = [("local", local)] if local else []
    if remote and remote != local:
        shas.append(("remote", remote))
    if not shas:
        return False, "no local or remote branch to judge", ()
    open_pr = bool(ctx.gh.pr_list(consumer.slug, head=branch, base=consumer.default_branch))
    evidence: list[str] = []
    verdicts: list[tuple[bool, str]] = []
    for label, sha in shas:
        _ensure_commit(ctx, consumer, sha, branch)
        ok, why = safety(ctx.git, consumer.dir, ctx.mirror, consumer, sha, d, open_pr)
        evidence.append(f"{label} {sha[:8]}: {why}")
        verdicts.append((ok, why))
    unsafe = [why for ok, why in verdicts if not ok]
    if unsafe:
        return False, unsafe[0], tuple(evidence)
    return True, "; ".join(dict.fromkeys(why for _, why in verdicts)), tuple(evidence)


def collect(ctx: CleanupContext, consumer: Consumer, *, version: str | None, remote: bool) -> list[Item]:
    fleet, foreign = _worktrees(ctx, consumer)
    local = _local_branches(ctx, consumer)
    remotes = _remote_branches(ctx, consumer) if remote else {}
    names = sorted(set(fleet) | foreign | set(local) | set(remotes))
    names = [n for n in names if version is None or parse_fleet_branch(n) == version]
    if not names:
        return []
    d = _default_head(ctx, consumer)
    items: list[Item] = []
    for name in names:
        ver = parse_fleet_branch(name)
        assert ver is not None
        where = (f"worktree {fleet[name]}" if name in fleet else "no fleet worktree",
                 f"local {local[name][:8]}" if name in local else "no local branch",
                 f"remote {remotes[name][:8]}" if name in remotes else "no remote branch in scope")
        try:
            safe, reason, evidence = _judge(ctx, consumer, name, d, local.get(name), remotes.get(name))
        except GitNetworkError:
            raise
        except GitError as exc:
            safe, reason, evidence = False, f"error: {exc}", ()
        if name in foreign:
            safe, reason = False, "checked out in a worktree that is not the fleet's"
        items.append(Item(consumer, name, ver, fleet.get(name), local.get(name), remotes.get(name),
                          where + evidence, safe, reason))
    return items


def ignored_allowed(path: str) -> bool:
    """An ignored path the fleet may delete with W: one of its components is on IGNORED_ALLOWLIST (any depth)."""
    return bool(IGNORED_ALLOWLIST_SET.intersection(path.rstrip("/").split("/")))


def fleet_node_modules(c: Consumer, w: Path) -> bool:
    """W/node_modules is the fleet's own symlink to the configured target."""
    link = w / "node_modules"
    return link.is_symlink() and os.readlink(link) == str(c.dir / "node_modules")


def _clean_worktree(git: Git, w: Path) -> str | None:
    """None when W is clean (ignored files only from the allowlist); otherwise why it is kept."""
    if git(w, "status", "--porcelain", "--untracked-files=all").stdout.strip():
        return "worktree has uncommitted or untracked files"
    out = git(w, "status", "--porcelain", "-z", "--ignored=matching").stdout.decode("utf-8", errors="surrogateescape")
    for entry in (e for e in out.split("\0") if e):
        if entry[:2] != "!!":
            return f"worktree is not clean ({entry[:2].strip() or '?'} {entry[3:]})"
        if not ignored_allowed(entry[3:]):
            return f"worktree has an ignored path outside the allowlist: {entry[3:]}"
    return None


def _tail(*texts: bytes) -> str:
    lines = [ln for t in texts for ln in t.decode("utf-8", errors="replace").strip().splitlines()]
    return " | ".join(lines[-3:]) or "no output"


def _execute(ctx: CleanupContext, item: Item) -> tuple[bool, str]:
    c, b, git = item.consumer, item.branch, ctx.git
    label = f"{c.short} {b}"

    unlinked = False

    def kept(why: str) -> tuple[bool, str]:
        return False, f"{label}: kept: {why}" + ("; node_modules symlink unlinked" if unlinked else "")

    fleet, foreign = _worktrees(ctx, c)
    if b in foreign:
        return kept("checked out in a worktree that is not the fleet's")
    w = fleet.get(b)
    if w is not None:
        if fleet_node_modules(c, w):   # 1. only the fleet's own symlink to the configured target
            (w / "node_modules").unlink()
            unlinked = True
        dirty = _clean_worktree(git, w)   # 2.
        if dirty:
            return kept(dirty)
    d = _default_head(ctx, c)   # 3.
    local = rev_parse(git, c.dir, f"refs/heads/{b}")
    remote = None
    if item.remote_head is not None:
        remote = ls_remote(git, c.dir, _planner(ctx).remote_url(c), f"refs/heads/{b}").get(f"refs/heads/{b}")
    safe, reason, _ = _judge(ctx, c, b, d, local, remote)
    if not safe:
        return kept(reason)
    done = []
    if remote is not None:   # 4. the remote first, from W (its hooks run there) or from the main clone
        pushed = git(w or c.dir, "push", f"--force-with-lease=refs/heads/{b}:{remote}", "origin", f":refs/heads/{b}",
                     check=False)
        if pushed.rc != 0:
            still = f"refs/heads/{b}" in ls_remote(git, c.dir, _planner(ctx).remote_url(c), f"refs/heads/{b}")
            if still:
                return kept(f"remote delete refused: {_tail(pushed.stderr, pushed.stdout)}")
        done.append("remote branch")
    if w is not None:   # 5. never --force; `worktree remove` deletes ignored files, so re-check just before
        dirty = _clean_worktree(git, w)
        if dirty:
            return kept(dirty + (" (remote branch already deleted)" if done else ""))
        removed = git(c.dir, "worktree", "remove", str(w), check=False)
        if removed.rc != 0:
            return kept(f"worktree remove refused: {_tail(removed.stderr, removed.stdout)}"
                        + (" (remote branch already deleted)" if done else ""))
        done.append("worktree")
    if local is not None:   # 6. compare-and-delete
        deleted = git(c.dir, "update-ref", "-d", f"refs/heads/{b}", local, check=False)
        if deleted.rc != 0:
            return kept(f"local branch not deleted: {_tail(deleted.stderr, deleted.stdout)}")
        done.append("local branch")
    tracking = rev_parse(git, c.dir, f"refs/remotes/origin/{b}")   # 7. only once ls-remote shows it gone
    if tracking is not None and f"refs/heads/{b}" not in ls_remote(
            git, c.dir, _planner(ctx).remote_url(c), f"refs/heads/{b}"):
        git(c.dir, "update-ref", "-d", f"refs/remotes/origin/{b}", tracking, check=False)
        done.append("tracking ref")
    return True, f"{label}: removed {', '.join(done) or 'nothing (already gone)'} ({reason})"


def execute(ctx: CleanupContext, item: Item) -> tuple[bool, str]:
    """Remove one item; every check is re-run now. (removed?, report line). A git error keeps the item."""
    try:
        return _execute(ctx, item)
    except GitNetworkError:
        raise
    except GitError as exc:
        return False, f"{item.consumer.short} {item.branch}: kept: error: {exc}"


def cleanup_landed(ctx: CleanupContext, consumer: Consumer, version: str) -> list[tuple[bool, str]]:
    """After a landed consumer: its leftovers of this version, remote branch first, under the land approval.

    One (removed?, report line) per item; a kept item (False) makes the run exit BLOCKED (spec 6.12)."""
    lines: list[tuple[bool, str]] = []
    for item in collect(ctx, consumer, version=version, remote=True):
        if item.safe:
            lines.append(execute(ctx, item))
        else:   # judged unsafe: reported, never executed (execute would unlink the node_modules symlink first)
            lines.append((False, f"{item.consumer.short} {item.branch}: kept: {item.reason}"))
    return lines


def _render(items: list[Item]) -> str:
    lines = ["Cleanup candidates:"]
    for i in items:
        lines.append(f"  {i.consumer.short}  {i.branch}  {'SAFE' if i.safe else 'KEEP'}  {i.reason}")
        lines += [f"      {line}" for line in i.evidence]
    if len(lines) == 1:
        lines.append("  none")
    return "\n".join(lines) + "\n"


def run_cleanup(deps: Deps, cfg: FleetConfig, tag: str | None, *, remote: bool) -> FleetExit:
    version = None
    if tag is not None:
        check_tag_syntax(tag)   # before any lock or git call
        version = tag[1:]
    lock = RunLock(deps.dirs.run_lock)
    if not lock.acquire(exclusive=True):
        raise UsageError("another guard-fleet run holds the lock")
    try:
        git, gh = _clients(deps)
        ctx = CleanupContext(deps, git, gh, refresh_mirror(deps, git), cfg)
        items: list[Item] = []
        for consumer in cfg.consumers:
            if consumer.dir.is_dir():
                items += collect(ctx, consumer, version=version, remote=remote)
        table = _render(items)
        safe = [i for i in items if i.safe]
        if not safe:
            deps.out.write(table)
            prune_tag_dirs(deps.dirs.state)
            return FleetExit.BLOCKED if items else FleetExit.OK
        ask(deps, table, reason_simple(f"cleanup {len(safe)} items", markers=agent_markers_present(deps.environ)))
        blocked = len(safe) < len(items)   # an unsafe item is a kept item
        for item in safe:
            removed, line = execute(ctx, item)
            deps.out.write(line + "\n")
            blocked = blocked or not removed
        prune_tag_dirs(deps.dirs.state)
        return FleetExit.BLOCKED if blocked else FleetExit.OK
    finally:
        lock.release()
