"""The bump PR body, ported from guard_bump.sh:188-216 (spec 3.10, 6.7 step 7)."""

from __future__ import annotations

from collections.abc import Sequence

from .config import Consumer
from .ledger import GATES
from .lockfile import LockParseError, parse_lock
from .roll import Rolled

# guard_bump.sh:49, the 4.x COMPAT_NOTE; its last sentence is dropped when the lock keeps an EXTRAS line.
COMPAT_NOTE = ("4.x removes `guard_core`; guard test fixtures are exempt only when listed in "
               "`self_skip.fixture_paths`.")
NO_EXTRAS_SENTENCE = "This PR adds no `EXTRAS` line."
MERGE_RULE = "**merge with a merge commit, never squash**"


def _lock_has_extras(rolled: Rolled) -> bool:
    """True unless the lock in W (checked byte-exact by G8) parses without an EXTRAS line."""
    if rolled.worktree is None:
        return True
    try:
        return parse_lock((rolled.worktree / "guard.lock").read_bytes()).extras != "none"
    except (OSError, LockParseError):
        return True   # never claim "no EXTRAS line" without having read it


def _commits(consumer: Consumer, tag: str) -> str:
    c2 = f"`guard.lock` and `scripts/guard`, copied byte-for-byte from `consumer/guard` at {tag}."
    if consumer.pin_kind == "none":
        return (f"One governance commit (no dev-dependency pin in this repo) — {MERGE_RULE}:\n\n"
                f"1. `chore(guard)`: {c2}")
    files = f"`{consumer.pin_file}`" + (" and `uv.lock`" if consumer.pin_kind == "pyproject" else "")
    # guard_bump also rewrote the expected pin in tests/ci/test_guard_pin.py (:134-136); the fleet does not.
    return (f"Two policy-isolated commits — {MERGE_RULE}:\n\n"
            f"1. `build(deps)`: the dev-dependency pin in {files} follows the new SHA.\n"
            f"2. `chore(guard)` (governance): {c2}")


def render(consumer: Consumer, *, version: str, p: str, t: str, rolled: Rolled, evidence: Sequence[str],
           deploy_line: str | None, running_tag: str, running_sha: str) -> str:
    tag = f"v{version}"
    compat = COMPAT_NOTE if _lock_has_extras(rolled) else f"{COMPAT_NOTE} {NO_EXTRAS_SENTENCE}"
    parts = [
        "## Summary",
        f"Bump agent-ratchet (formerly guard-core) from `{p[:8]}` to {tag} (`{t}`).",
        _commits(consumer, tag),
        f"{compat} See the agent-ratchet CHANGELOG for {tag}.",
        "## Verification",
    ]
    rows = ["| gate | verdict | log |", "|---|---|---|"]
    for gate in GATES:   # n/a rows included; a gate without a result shows as not run
        verdict, log = rolled.gates.get(gate, ("not run", ""))
        rows.append(f"| {gate} | {verdict} | {f'`{log}`' if log else ''} |")
    parts.append("\n".join(rows))
    parts.append(rolled.hooks)
    if evidence:
        parts.append("Classification evidence:\n\n" + "\n".join(f"- {line}" for line in evidence))
    if deploy_line:
        parts.append(deploy_line)
    parts.append(f"Opened by guard-fleet {running_tag} ({running_sha[:8]}).")
    return "\n\n".join(parts) + "\n"
