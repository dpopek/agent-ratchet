"""G8, the strict shape of a bump: BASE..H holds exactly the fleet's C1 and C2 and their bytes (spec 6.7)."""

from __future__ import annotations

import tomllib
from pathlib import Path

from .classify.canonical import canonical_toml
from .config import Consumer
from .gates import NO_LOG, GateResult
from .git import Git, GitError, diff_name_status, show_bytes
from .lockfile import render_lock
from .pins import PinError, rewrite_pin

LOCK, SHIM, UV_LOCK = "guard.lock", "scripts/guard", "uv.lock"
AGENT_RATCHET = "agent-ratchet"


class ShapeError(Exception):
    """BASE..H is not the shape the fleet writes."""


def _replace_strings(value: object, p: str, t: str) -> object:
    if isinstance(value, str):
        return value.replace(p, t)
    if isinstance(value, dict):
        return {_replace_strings(k, p, t): _replace_strings(v, p, t) for k, v in value.items()}
    if isinstance(value, list):
        return [_replace_strings(v, p, t) for v in value]
    return value


def _drop_agent_ratchet(data: dict) -> dict:
    packages = data.get("package")
    if not isinstance(packages, list):
        return data
    kept = [pkg for pkg in packages if not (isinstance(pkg, dict) and pkg.get("name") == AGENT_RATCHET)]
    return {**data, "package": kept}


def uvlock_equal(base: bytes, head: bytes, p: str, t: str) -> bool:
    """BASE and H parse equal once every agent-ratchet [[package]] is dropped and P reads as T on the base side."""
    try:
        b = tomllib.loads(base.decode("utf-8"))
        h = tomllib.loads(head.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError):
        return False
    b = _drop_agent_ratchet(_replace_strings(b, p, t))   # type: ignore[arg-type]
    return canonical_toml(b) == canonical_toml(_drop_agent_ratchet(h))


def _commits(git: Git, repo: Path, base: str, head: str) -> list[str]:
    """The commits of BASE..H, oldest first; raises unless they form one linear chain on BASE ending at H."""
    lines = git(repo, "rev-list", "--reverse", "--parents", f"{base}..{head}").text.split("\n")
    chain = [line.split() for line in lines if line.strip()]
    parent = git(repo, "rev-parse", "--verify", f"{base}^{{commit}}").text.strip()
    for entry in chain:
        if len(entry) != 2 or entry[1] != parent:
            raise ShapeError(f"BASE..H is not a linear chain of single-parent commits on BASE ({entry[0][:12]})")
        parent = entry[0]
    if chain and chain[-1][0] != git(repo, "rev-parse", "--verify", f"{head}^{{commit}}").text.strip():
        raise ShapeError("BASE..H does not end at H")
    return [entry[0] for entry in chain]


def _touched(git: Git, repo: Path, commit: str) -> set[str]:
    out = git(repo, "diff-tree", "--no-commit-id", "--name-only", "-r", "-z", "--no-renames", f"{commit}^",
              commit).stdout.decode("utf-8", errors="surrogateescape")
    return {path for path in out.split("\0") if path}


def _mode(git: Git, repo: Path, rev: str, path: str) -> str | None:
    out = git(repo, "ls-tree", "-z", rev, "--", path).stdout.decode("utf-8", errors="surrogateescape")
    return out.split(" ", 1)[0] if out else None


def _problems(git: Git, repo: Path, mirror: Path, consumer: Consumer, *, base: str, head: str, p: str, t: str,
              extras: str) -> list[str]:
    pin = consumer.pin_file if consumer.pin_kind != "none" else None
    uv = consumer.pin_kind == "pyproject"
    c1_paths = ({pin} if pin else set()) | ({UV_LOCK} if uv else set())
    allowed = c1_paths | {LOCK, SHIM}
    problems: list[str] = []

    changed = diff_name_status(git, repo, base, head)
    names = {path for _, path in changed}
    if names - allowed:
        problems.append(f"paths outside the bump: {sorted(names - allowed)}")
    deleted = sorted(path for status, path in changed if status == "D")
    if deleted:
        problems.append(f"deleted: {deleted}")
    if LOCK not in names:
        problems.append("guard.lock is unchanged")

    expected = 2 if pin else 1
    commits = _commits(git, repo, base, head)
    if len(commits) != expected:
        problems.append(f"{len(commits)} commits in BASE..H, expected {expected}")
    else:
        if pin:
            c1 = _touched(git, repo, commits[0])
            if not c1 <= c1_paths or pin not in c1:
                problems.append(f"C1 touches {sorted(c1)}, allowed only {sorted(c1_paths)}")
        c2 = _touched(git, repo, commits[-1])
        if not c2 <= {LOCK, SHIM} or LOCK not in c2:
            problems.append(f"C2 touches {sorted(c2)}, allowed only ['guard.lock', 'scripts/guard']")

    if pin:
        before, after = show_bytes(git, repo, base, pin), show_bytes(git, repo, head, pin)
        if before is None or after is None:
            problems.append(f"{pin} is missing at {'BASE' if before is None else 'H'}")
        else:
            try:
                if rewrite_pin(before, p, t) != after:
                    problems.append(f"{pin} at H is not BASE's {pin} with only the pin SHA changed")
            except PinError as exc:
                problems.append(f"{pin} at BASE: {exc}")
    if show_bytes(git, repo, head, LOCK) != render_lock(t, extras):
        problems.append(f"guard.lock at H is not {render_lock(t, extras)!r}")
    shim = show_bytes(git, mirror, t, "consumer/guard")
    if shim is None:
        problems.append("consumer/guard is missing at T")
    elif show_bytes(git, repo, head, SHIM) != shim:
        problems.append("scripts/guard at H is not T:consumer/guard")
    mode = _mode(git, repo, head, SHIM)
    if mode != "100755":
        problems.append(f"scripts/guard at H has mode {mode}, expected 100755")
    if uv:
        before, after = show_bytes(git, repo, base, UV_LOCK), show_bytes(git, repo, head, UV_LOCK)
        if before is None or after is None or not uvlock_equal(before, after, p, t):
            problems.append("uv.lock differs from BASE beyond the agent-ratchet entry and P -> T")
    return problems


def check(git: Git, repo: Path, mirror: Path, consumer: Consumer, *, base: str, head: str, p: str, t: str,
          extras: str) -> GateResult:
    """G8. The caller (run_gates) gives the result its log path; cleanup and resume use the same check."""
    try:
        problems = _problems(git, repo, mirror, consumer, base=base, head=head, p=p, t=t, extras=extras)
    except (ShapeError, GitError, OSError) as exc:
        problems = [str(exc)]
    if problems:
        return GateResult("G8", "FAIL", "G8: " + "; ".join(problems), None, None, NO_LOG)
    return GateResult("G8", "PASS", "G8: BASE..H is exactly the fleet's bump", None, None, NO_LOG)
