"""The read-only `plan`: per consumer, does the release T reach it (SKIP), need a bump (BUMP), or is it blocked."""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .classify.decision import classify_release, decide, evidence_lines
from .config import Consumer, FleetConfig
from .deps import Deps
from .env import base_child_env
from .exits import FleetExit, combine
from .exposure import Exposure, TreeScan, compute_exposure, tree_scan
from .gh import Gh, GhAuthError, GhError, GhNetworkError, GhNotFound
from .git import Git, GitError, GitNetworkError, fetch_default, has_commit, ls_remote
from .lockfile import LockParseError, LockSpec, parse_lock
from .locks import RunLock
from .mirror import mirror_readonly, refresh_mirror
from .profile import parse_profile
from .target import Target, newest_v4_tag, pin_relation, release_tag_for, validate_target

CONFIG_PATH = "scripts/audit/audit_guard_config.json"


@dataclass(frozen=True)
class PlanRow:
    short: str
    pin_tag: str | None
    p: str | None
    extras: str
    t: str
    d: str | None
    decision: Literal["CURRENT", "SKIP", "BUMP", "BLOCKED"]
    reason: str
    evidence: tuple[str, ...]
    exposure: Exposure | None
    provisional: bool


@dataclass(frozen=True)
class PlanResult:
    target: Target
    rows: tuple[PlanRow, ...]
    mirror_note: str | None
    exit: FleetExit


class Planner:
    def __init__(self, deps: Deps, git: Git, gh: Gh, mirror: Path, *, lock_free: bool) -> None:
        self.deps = deps
        self.git = git
        self.gh = gh
        self.mirror = mirror
        self.lock_free = lock_free
        self.gh_stopped = False   # a gh auth or network failure ended some row: the run exits 4

    def remote_url(self, consumer: Consumer) -> str:
        return f"https://github.com/{consumer.slug}"

    def plan_consumer(self, consumer: Consumer, target: Target, *, include_unexposed: bool) -> PlanRow:
        try:
            return self._plan(consumer, target, include_unexposed)
        except (GhAuthError, GhNetworkError) as exc:
            self.gh_stopped = True
            kind = "auth" if isinstance(exc, GhAuthError) else "network"
            return self._blocked(consumer, target, f"gh {kind}: {exc.message}")
        except GitNetworkError as exc:
            self.gh_stopped = True
            return self._blocked(consumer, target, f"network: {exc}")
        except (GhError, GitError) as exc:
            return self._blocked(consumer, target, str(exc))

    # -- internals ---------------------------------------------------------------------------------------

    def _blocked(self, consumer: Consumer, target: Target, reason: str, *, d: str | None = None,
                 lock: LockSpec | None = None, pin_tag: str | None = None) -> PlanRow:
        return PlanRow(consumer.short, pin_tag, lock.sha if lock else None, lock.extras if lock else "",
                       target.sha, d, "BLOCKED", reason, (), None, False)

    def _plan(self, consumer: Consumer, target: Target, include_unexposed: bool) -> PlanRow:
        slug = consumer.slug
        try:
            self.gh.repo_visible(slug)
        except GhNotFound:
            return self._blocked(consumer, target, f"repo not visible to gh account {self.gh.user_login()}")
        if not consumer.dir.is_dir():
            return self._blocked(consumer, target, "consumer checkout directory is missing")
        ref = f"refs/heads/{consumer.default_branch}"
        for attempt in (0, 1):   # a second pass only when the branch moved while D was being fetched
            d = ls_remote(self.git, self.mirror, self.remote_url(consumer), ref).get(ref)
            if d is None:
                return self._blocked(consumer, target, f"default branch {consumer.default_branch} not found")
            raw_lock = self.gh.contents_raw(slug, "guard.lock", d)
            if raw_lock is None:
                return self._blocked(consumer, target, f"no guard.lock at {d}", d=d)
            try:
                lock = parse_lock(raw_lock)
            except LockParseError:
                return self._blocked(consumer, target, "guard.lock unparseable", d=d)
            pin_tag = release_tag_for(self.git, self.mirror, lock.sha)
            if pin_tag is None:
                return self._blocked(consumer, target, "untagged pin", d=d, lock=lock)
            relation = pin_relation(self.git, self.mirror, lock.sha, target.sha)
            if relation == "current":
                return PlanRow(consumer.short, pin_tag, lock.sha, lock.extras, target.sha, d, "CURRENT",
                               f"pin {pin_tag} is at or beyond {target.tag}", (), None, False)
            if relation == "diverged":
                return self._blocked(consumer, target, "pin diverged from target", d=d, lock=lock, pin_tag=pin_tag)
            profile = parse_profile(self.gh.contents_raw(slug, CONFIG_PATH, d))
            scan = self._scan(consumer, d)
            if scan is not None:
                break
            if attempt == 1:
                return self._blocked(consumer, target, "D not fetchable", d=d, lock=lock, pin_tag=pin_tag)
        rel = classify_release(self.git, self.mirror, lock.sha, target.sha)
        exposure = compute_exposure(profile, lock, consumer, scan)
        decision = decide(rel, exposure, include_unexposed=include_unexposed)
        provisional = decision == "SKIP" and (self.lock_free or scan.skipped is not None)
        return PlanRow(consumer.short, pin_tag, lock.sha, lock.extras, target.sha, d, decision,
                       self._why(rel, exposure, decision, include_unexposed), tuple(evidence_lines(rel)),
                       exposure, provisional)

    def _scan(self, consumer: Consumer, d: str) -> TreeScan | None:
        """The tree scan of D in the consumer's checkout; None when D cannot be fetched there."""
        if self.lock_free:
            if not has_commit(self.git, consumer.dir, d):
                return TreeScan(frozenset(), (), "lock-free: D not in clone")
            return tree_scan(self.git, consumer.dir, d)
        fetch_default(self.git, consumer.dir, consumer.default_branch)
        if not has_commit(self.git, consumer.dir, d):
            return None
        return tree_scan(self.git, consumer.dir, d)

    @staticmethod
    def _why(rel, exposure: Exposure, decision: str, include_unexposed: bool) -> str:
        if rel.fingerprint_mismatch:
            return "unreviewed predicate fingerprint: every surface counts as exposed"
        if include_unexposed and decision == "BUMP" and (rel.min_level is None or exposure.level < rel.min_level):
            return "--include-unexposed"
        if rel.min_level is None:
            return "release changes metadata only"
        name = rel.min_level.name.lower()
        if decision == "BUMP":
            return f"changed {name} surface is within exposure {exposure.level.name.lower()}"
        return f"changed surfaces start at {name}; exposure is {exposure.level.name.lower()}"


def _clients(deps: Deps) -> tuple[Git, Gh]:
    env = base_child_env(deps.environ, tool_bin=Path(sys.prefix) / "bin")
    return Git(deps.run, env, deps.sleep), Gh(deps.run, env, deps.sleep, deps.dirs.home)


def run_plan(deps: Deps, cfg: FleetConfig, tag: str | None, *, only: tuple[str, ...],
             include_unexposed: bool) -> PlanResult:
    for short in only:
        cfg.by_short(short)   # unknown short: UsageError before any network or lock work
    consumers = tuple(c for c in cfg.consumers if not only or c.short in only)
    git, gh = _clients(deps)
    lock = RunLock(deps.dirs.run_lock)
    lock_free = not lock.acquire(exclusive=False)
    try:
        if lock_free:
            mirror, stamp = mirror_readonly(deps)
            note: str | None = f"mirror as of {stamp}"
        else:
            mirror, note = refresh_mirror(deps, git), None
        target = validate_target(git, mirror, tag) if tag is not None else newest_v4_tag(git, mirror)
        planner = Planner(deps, git, gh, mirror, lock_free=lock_free)
        rows = tuple(planner.plan_consumer(c, target, include_unexposed=include_unexposed) for c in consumers)
    finally:
        lock.release()
    codes = [FleetExit.BLOCKED for r in rows if r.decision == "BLOCKED"]
    if planner.gh_stopped:
        codes.append(FleetExit.CANCELLED)
    return PlanResult(target, rows, note, combine(codes))
