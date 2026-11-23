"""The fleet's self-check: the running commit must be a published, annotated v4 release."""

from __future__ import annotations

import importlib.metadata
import json
import re
from pathlib import Path

from .exits import ShaMismatch, UsageError
from .git import Git
from .target import TAG_RE, TargetError, release_tag_for, validate_target

DIST = "agent-ratchet-fleet"
_SHA_RE = re.compile(r"[0-9a-f]{40}")


class SelfCheckError(UsageError):
    """The running fleet failed a self-check: exit 2."""


def installed_sha(dist: str = DIST) -> str | None:
    """Commit the distribution was installed from (PEP 610), or None for non-VCS installs.

    Same read as src/agent_ratchet/version.py at c305de7 (L15-25), but only a 40-hex
    lower-case commit counts.
    """
    try:
        raw = importlib.metadata.distribution(dist).read_text("direct_url.json")
    except importlib.metadata.PackageNotFoundError:
        return None
    if not raw:
        return None
    try:
        payload = json.loads(raw)
    except ValueError:
        return None
    vcs_info = payload.get("vcs_info") if isinstance(payload, dict) else None
    commit = vcs_info.get("commit_id") if isinstance(vcs_info, dict) else None
    return commit if isinstance(commit, str) and _SHA_RE.fullmatch(commit) else None


def check_expect_sha(expect: str, installed: str | None) -> None:
    if not _SHA_RE.fullmatch(expect):
        raise UsageError("--expect-sha must be 40 lower-case hex characters")
    if expect != installed:
        raise ShaMismatch(f"--expect-sha {expect} != installed commit {installed}")


def self_check(git: Git, mirror: Path, running: str, *, target_sha: str | None) -> str:
    """Return the v4 tag the running commit peels from, or raise SelfCheckError."""
    tag = release_tag_for(git, mirror, running)
    if tag is None or not TAG_RE.fullmatch(tag):
        raise SelfCheckError(f"self-check: no v4 tag peels to {running}")
    try:
        validate_target(git, mirror, tag)  # annotated, reachable from main, ls-remote peel
    except TargetError as exc:
        raise SelfCheckError(f"self-check: running tag {tag}: {exc}") from exc
    if target_sha is not None and running == target_sha:
        raise SelfCheckError(f"self-check: running fleet equals the target ({tag}); the fleet never rolls the tag it runs from")
    return tag
