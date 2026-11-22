"""Release classification P..T and the per-consumer decision (spec §6.5 "Decision")."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol

from ..git import Git, diff_name_status
from .changes import ChangedPath, classify_path
from .fingerprints import mismatches
from .gating import Level
from .surfaces import compute_surfaces
from .tree import load_tree


class HasLevel(Protocol):
    """The part of a consumer's exposure the decision reads."""

    @property
    def level(self) -> Level: ...


@dataclass(frozen=True)
class ReleaseClass:
    p: str   # the commit P resolves to
    t: str   # the commit T resolves to
    changes: tuple[ChangedPath, ...]
    min_level: Level | None             # lowest surface changed; None when every change is metadata
    all_core_reason: str | None         # set → min_level is CORE
    fingerprint_mismatch: tuple[str, ...]   # target ids unreviewed at P or at T


# Content-addressed by (mirror, commit P, commit T), so one run computes each pair once.
_CACHE: dict[tuple[str, str, str], ReleaseClass] = {}


def classify_release(git: Git, mirror: Path, p: str, t: str) -> ReleaseClass:
    p_sha = _commit(git, mirror, p)
    t_sha = _commit(git, mirror, t)
    key = (str(Path(mirror).resolve()), p_sha, t_sha)
    cached = _CACHE.get(key)
    if cached is not None:
        return cached
    p_tree, t_tree = load_tree(git, mirror, p_sha), load_tree(git, mirror, t_sha)
    p_map, t_map = compute_surfaces(p_tree), compute_surfaces(t_tree)
    changes = tuple(classify_path(path, status, p_tree=p_tree, t_tree=t_tree, p_map=p_map, t_map=t_map)
                    for status, path in diff_name_status(git, mirror, p_sha, t_sha))
    reasons = [f"at {side}: {m.all_core_reason}" for side, m in (("P", p_map), ("T", t_map)) if m.all_core_reason]
    levels = [c.level for c in changes if c.level is not None]
    rel = ReleaseClass(
        p=p_sha,
        t=t_sha,
        changes=changes,
        min_level=Level.CORE if reasons else min(levels, default=None),
        all_core_reason=reasons[0] if reasons else None,
        fingerprint_mismatch=tuple(sorted(set(mismatches(p_tree)) | set(mismatches(t_tree)))),
    )
    _CACHE[key] = rel
    return rel


def _commit(git: Git, mirror: Path, rev: str) -> str:
    return git(mirror, "rev-parse", "--verify", "--quiet", f"{rev}^{{commit}}").text.strip()


def decide(rel: ReleaseClass, exposure: HasLevel, *, include_unexposed: bool) -> Literal["SKIP", "BUMP"]:
    """BUMP when the lowest changed surface is within the exposure; an unreviewed fingerprint exposes every
    surface; `include_unexposed` turns every SKIP into BUMP."""
    effective = Level.MAGENTO if rel.fingerprint_mismatch else exposure.level
    if include_unexposed or (rel.min_level is not None and effective >= rel.min_level):
        return "BUMP"
    return "SKIP"


def evidence_lines(rel: ReleaseClass) -> list[str]:
    lines = [f"{c.path} [{c.level.name.lower()}]" for c in rel.changes if c.level is not None]
    if rel.all_core_reason:
        lines.append(f"all core: {rel.all_core_reason}")
    if rel.fingerprint_mismatch:
        lines.append("fingerprint mismatch: " + ", ".join(rel.fingerprint_mismatch))
    return lines
