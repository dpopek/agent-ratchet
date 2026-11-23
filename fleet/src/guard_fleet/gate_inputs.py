"""Gate inputs: the paths whose change between BASE and a later D' invalidates the local gates (spec 6.7)."""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path

from .config import Consumer
from .git import Git
from .lockfile import spec_url
from .proc import Runner, low_priority_prefix

ASK_TIMEOUT = 1800
ALWAYS_GLOBS = ("scripts/audit/**", "tests/ci/**")

# Runs inside `uv run --with <SPEC>`, so the release's own rules answer (the sanctioned exception to "the fleet
# never imports agent_ratchet"). At c305de7, git_guard_io.py:173 `is_protected_governance_path(rel_path: str)
# -> bool`; :151 `is_package_json_path(rel_path: str) -> bool`; :167 `package_json_guarded_change(old_raw:
# bytes | None, new_raw: bytes | None) -> bool`. The last two exist from v4.3.0 on, so an older release flags no
# package.json. The ask carries paths only, not the BASE/D' blob pair package_json_guarded_change compares, so
# every package.json is read as a guarded change (its fail-closed answer for an unknown pair).
ASK_SCRIPT = """\
import json, sys
from agent_ratchet.git_guard_io import is_protected_governance_path
try:
    from agent_ratchet.git_guard_io import is_package_json_path, package_json_guarded_change
except ImportError:
    is_package_json_path = package_json_guarded_change = None
paths = json.load(sys.stdin)
if not isinstance(paths, list) or not all(isinstance(p, str) for p in paths):
    sys.exit("expected a JSON list of paths on stdin")
flagged = set()
for p in paths:
    if is_protected_governance_path(p):
        flagged.add(p)
    elif package_json_guarded_change is not None and is_package_json_path(p):
        flagged.add(p)
json.dump(sorted(flagged), sys.stdout)
"""


class AskError(RuntimeError):
    """agent-ratchet could not say which paths it protects; the caller must not assume none."""


def protected_paths(run: Runner, env: Mapping[str, str], cwd: Path, spec: str,
                    paths: Sequence[str]) -> frozenset[str]:
    argv = (*low_priority_prefix(), "uv", "run", "--isolated", "--no-config", "--no-project", "--with", spec,
            "python", "-I", "-c", ASK_SCRIPT)
    res = run(argv, cwd=cwd, env=env, timeout=ASK_TIMEOUT, input=json.dumps(list(paths)).encode("utf-8"))
    if res.timed_out or res.rc != 0:
        raise AskError(f"asking {spec} for protected paths failed (rc {res.rc}): "
                       f"{res.stderr.decode('utf-8', errors='replace').strip()[-500:]}")
    try:
        out = json.loads(res.stdout.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise AskError(f"{spec} answered with no JSON list: {exc}") from exc
    if not isinstance(out, list) or not all(isinstance(p, str) for p in out) or not set(out) <= set(paths):
        raise AskError(f"{spec} answered with something other than a subset of the asked paths")
    return frozenset(out)


def _names(git: Git, repo: Path, *args: str) -> set[str]:
    out = git(repo, *args).stdout.decode("utf-8", errors="surrogateescape")
    return {p for p in out.split("\0") if p}


def gate_inputs(run: Runner, env: Mapping[str, str], git: Git, worktree: Path, consumer: Consumer, *, base: str,
                d: str, p: str, t: str, extras: str, g7_files: Iterable[str]) -> frozenset[str]:
    """Paths flagged at SPEC(P) or SPEC(T) among the candidates, plus the pin file, uv.lock, scripts/audit/**,
    tests/ci/** and the files G7 read."""
    always = {"uv.lock", *g7_files} | ({consumer.pin_file} if consumer.pin_file else set())
    for rev in (base, d):
        always |= _names(git, worktree, "ls-tree", "-r", "-z", "--name-only", rev, "--", "scripts/audit", "tests/ci")
    diff = _names(git, worktree, "diff", "--name-only", "-z", "--no-renames", base, d)
    candidates = sorted(diff | always)
    flagged: set[str] = set()
    for sha in (p, t):
        flagged |= protected_paths(run, env, worktree, spec_url(sha, extras), candidates)
    return frozenset(flagged | always)


def _matches(path: str, glob: str) -> bool:
    if glob.endswith("/**"):
        return path.startswith(glob[:-2])
    return path == glob


def touches(paths: Iterable[str], inputs: frozenset[str], globs: Sequence[str] = ALWAYS_GLOBS) -> list[str]:
    """The paths, in order and once each, that are gate inputs or fall under one of the globs."""
    out: list[str] = []
    for path in paths:
        if path not in out and (path in inputs or any(_matches(path, g) for g in globs)):
            out.append(path)
    return out
