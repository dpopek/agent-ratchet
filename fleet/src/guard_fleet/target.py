"""Release-target validation against the mirror and the upstream remote."""

from __future__ import annotations

import re
from pathlib import Path
from dataclasses import dataclass
from typing import Literal

from .exits import UsageError
from .git import Git, is_ancestor, ls_remote, object_type, rev_parse
from .mirror import UPSTREAM_URL

TAG_RE = re.compile(r"v4\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
RELEASE_TAG_RE = re.compile(r"\Av(3|4)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z")


@dataclass(frozen=True)
class Target:
    tag: str
    sha: str
    version: tuple[int, int, int]


class TargetError(UsageError):
    """A release target failed a validation check."""


def check_tag_syntax(tag: str) -> tuple[int, int, int]:
    match = TAG_RE.fullmatch(tag) if tag.isascii() else None
    if match is None:
        raise TargetError(f"tag syntax: {tag!r} is not a v4.MINOR.PATCH release tag")
    return 4, int(match.group(1)), int(match.group(2))


def validate_target(git: Git, mirror: Path, tag: str) -> Target:
    version = check_tag_syntax(tag)
    ref = f"refs/tags/{tag}"
    kind = object_type(git, mirror, ref)
    if kind is None:
        raise TargetError(f"tag {tag} does not exist in the mirror")
    if kind != "tag":
        raise TargetError(f"tag {tag} is not annotated")
    sha = rev_parse(git, mirror, f"{ref}^{{commit}}")
    if sha is None:
        raise TargetError(f"tag {tag} does not peel to a commit")
    if not is_ancestor(git, mirror, sha, "refs/heads/main"):
        raise TargetError(f"tag {tag} is not reachable from main")
    peeled = f"{ref}^{{}}"  # ls-remote lists the peeled row only when asked for it by name
    remote = ls_remote(git, mirror, UPSTREAM_URL, peeled).get(peeled)
    if remote != sha:
        raise TargetError(f"tag {tag}: ls-remote peel differs from the mirror ({remote} != {sha})")
    return Target(tag, sha, version)


def _tag_names(git: Git, mirror: Path, *patterns: str) -> list[str]:
    out = git(mirror, "for-each-ref", "--format=%(refname)", *patterns).text
    return [line.removeprefix("refs/tags/") for line in out.splitlines() if line]


def newest_v4_tag(git: Git, mirror: Path) -> Target:
    """Highest annotated v4 tag reachable from main; the winner goes through the full validation."""
    candidates: list[tuple[tuple[int, int, int], str]] = []
    for name in _tag_names(git, mirror, "refs/tags/v4.*"):
        if not (name.isascii() and TAG_RE.fullmatch(name)):
            continue
        ref = f"refs/tags/{name}"
        sha = rev_parse(git, mirror, f"{ref}^{{commit}}")
        if object_type(git, mirror, ref) == "tag" and sha and is_ancestor(git, mirror, sha, "refs/heads/main"):
            candidates.append((check_tag_syntax(name), name))
    if not candidates:
        raise TargetError("no annotated v4 release tag reachable from main")
    return validate_target(git, mirror, max(candidates)[1])


def release_tag_for(git: Git, mirror: Path, sha: str) -> str | None:
    """Lowest-version annotated v3/v4 release tag that peels to ``sha``."""
    found: list[tuple[tuple[int, ...], str]] = []
    for name in _tag_names(git, mirror, "refs/tags/v3.*", "refs/tags/v4.*"):
        match = RELEASE_TAG_RE.match(name)
        ref = f"refs/tags/{name}"
        if match and object_type(git, mirror, ref) == "tag" and rev_parse(git, mirror, f"{ref}^{{commit}}") == sha:
            found.append((tuple(int(g) for g in match.groups()), name))
    return min(found)[1] if found else None


def pin_relation(git: Git, mirror: Path, p: str, t: str) -> Literal["current", "candidate", "diverged"]:
    if p == t or is_ancestor(git, mirror, t, p):
        return "current"
    if is_ancestor(git, mirror, p, t):
        return "candidate"
    return "diverged"
