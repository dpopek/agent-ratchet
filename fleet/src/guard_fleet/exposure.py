"""Which release surfaces a consumer can reach: its profile, lock extras, declared surfaces and a scan of its tree."""

from __future__ import annotations

import ast
import io
import re
import shlex
import tokenize
from dataclasses import dataclass
from pathlib import Path

from .classify.gating import Level
from .config import Consumer
from .git import Git, GitError
from .lockfile import LockSpec
from .profile import Profile, magento_active, php_active

# Prose cannot import, and a doc mention never executes; cost if wrong: a doc mention is ignored.
SCAN_EXCLUDES = (":(exclude,glob)**/*.md", ":(exclude,glob)docs/**")

_SURFACE_RE = re.compile(r"agent_ratchet\.(php|magento)")
_HIT_RE = re.compile(r"^(.*?):(\d+):(.*)$", re.S)
_MODULE_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*")
_DYNAMIC_MARKERS = ("importlib", "__import__", "runpy", "-m agent_ratchet")
_EXEC_MARKER = "scripts/guard exec"
_LEVEL_OF = {"php": Level.PHP, "magento": Level.MAGENTO}


@dataclass(frozen=True)
class TreeScan:
    levels: frozenset[Level]
    evidence: tuple[str, ...]
    skipped: str | None = None


@dataclass(frozen=True)
class Exposure:
    level: Level
    reasons: tuple[str, ...]
    tree_scan: TreeScan


def _grep(git: Git, repo: Path, *args: str) -> list[tuple[str, int, str]]:
    """`git grep -z -n -a` hits (-a: a consumer's .gitattributes cannot hide a line by marking it binary) as (path, line number, text); rc 1 is no hit, any other failure raises."""
    r = git(repo, "grep", "-z", "-n", "-a", *args, check=False)
    if r.rc == 1:
        return []
    if r.rc != 0:
        raise GitError(r)
    hits: list[tuple[str, int, str]] = []
    for record in r.stdout.split(b"\n"):
        if not record:
            continue
        head, number, text = record.split(b"\0", 2)
        path = head.decode("utf-8", errors="surrogateescape").partition(":")[2]  # drop the "<tree>:" prefix
        hits.append((path, int(number), text.decode("utf-8", errors="replace")))
    return hits


def tree_scan(git: Git, repo: Path, d: str) -> TreeScan:
    levels: set[Level] = set()
    evidence: list[str] = []
    for path, number, text in _grep(git, repo, "-E", r"agent_ratchet\.(php|magento)", d, "--", ".", *SCAN_EXCLUDES):
        for name in sorted(set(_SURFACE_RE.findall(text))):
            levels.add(_LEVEL_OF[name])
            evidence.append(f"agent_ratchet.{name} imported: {path}:{number} [{name}]")
    for path, number, text in _grep(git, repo, "-F", _EXEC_MARKER, d, "--", ".", ":(exclude)scripts/guard",
                                    *SCAN_EXCLUDES):
        level, note = resolve_guard_exec(git, repo, d, f"{path}:{number}:{text}")
        if level is not Level.CORE:
            levels.add(level)
            evidence.append(note)
    return TreeScan(frozenset(levels), tuple(evidence))


def _opaque(where: str) -> tuple[Level, str]:
    return Level.MAGENTO, f"opaque guard exec: {where}"


def _module_level(module: str) -> Level:
    for name, level in _LEVEL_OF.items():
        prefix = f"agent_ratchet.{name}"
        if module == prefix or module.startswith(prefix + "."):
            return level
    return Level.CORE


def resolve_guard_exec(git: Git, repo: Path, d: str, line: str) -> tuple[Level, str]:
    """The surface a `scripts/guard exec` line runs: (level, evidence). `line` is `<file>:<lineno>:<text>`.

    Usage at the pinned core: `scripts/guard exec [--lock-from REF] [--] <cmd...>`. Resolved: `python[3] [-I] -m
    <mod>`, `agent-ratchet ...` and `python[3] [-I] <tracked>.py` without a dynamic import form. Everything else is
    opaque and counts as every surface."""
    match = _HIT_RE.match(line)
    where = f"{match.group(1)}:{match.group(2)}" if match else line
    text = match.group(3) if match else line
    found = [_resolve_one(git, repo, d, where, rest) if rest is not None else _opaque(where)
             for rest in _exec_texts(where, text)] or [_opaque(where)]
    level = max(level for level, _ in found)
    notes = [note for lvl, note in found if lvl is not Level.CORE] or [found[0][1]]
    return level, "; ".join(notes)   # every occurrence on the line counts; each non-core one is evidenced


def _exec_texts(where: str, text: str) -> list[str | None]:
    """The command texts following each marker; None marks one that cannot be resolved (opaque).

    A `.py` line is tokenized: a marker inside plain str literals is resolved from the literal's value (a test that
    asserts the text of its own wrapper does not run it). A marker anywhere else (comment, f-string on 3.12+,
    code), or a line that does not tokenize on its own, keeps the whole-line split."""
    whole = text.split(_EXEC_MARKER)[1:]
    if not where.rpartition(":")[0].endswith(".py"):
        return whole
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(text).readline))
    except (tokenize.TokenError, SyntaxError):
        return whole
    strings = [t.string for t in tokens if t.type == tokenize.STRING and _EXEC_MARKER in t.string]
    if sum(s.count(_EXEC_MARKER) for s in strings) != text.count(_EXEC_MARKER):
        return whole   # a marker outside every STRING token
    out: list[str | None] = []
    for s in strings:
        try:
            value = ast.literal_eval(s)
        except (ValueError, SyntaxError):
            value = None
        if isinstance(value, str):
            out += value.split(_EXEC_MARKER)[1:]
        else:
            out.append(None)   # f-string (3.11), bytes or anything else that is not a plain literal
    return out


def _resolve_one(git: Git, repo: Path, d: str, where: str, rest: str) -> tuple[Level, str]:
    try:
        tokens = shlex.split(rest)
    except ValueError:
        return _opaque(where)
    i = 0
    if tokens[i:i + 1] == ["--lock-from"]:
        i += 2
    if tokens[i:i + 1] == ["--"]:
        i += 1
    cmd = tokens[i:]
    if not cmd:
        return _opaque(where)
    if cmd[0] == "agent-ratchet":
        return Level.CORE, f"guard exec agent-ratchet: {where}"
    if cmd[0] not in ("python", "python3"):
        return _opaque(where)
    args = cmd[1:]
    if args[:1] == ["-I"]:
        args = args[1:]
    if not args:
        return _opaque(where)
    if args[0] == "-m":
        module = args[1] if len(args) > 1 else ""
        if not _MODULE_RE.fullmatch(module):
            return _opaque(where)
        level = _module_level(module)
        return level, f"guard exec -m {module}: {where} [{level.name.lower()}]"
    script = args[0]
    if script.endswith(".py") and _plain_relative(script):
        body = _regular_blob(git, repo, d, script)
        if body is not None:
            source = body.decode("utf-8", errors="replace")
            if not any(marker in source for marker in _DYNAMIC_MARKERS):
                return Level.CORE, f"guard exec {script}: {where}"  # its static imports are covered by the tree grep
    return _opaque(where)


def _regular_blob(git: Git, repo: Path, d: str, path: str) -> bytes | None:
    """The content of a tracked regular file (mode 100644 or 100755) at d; None for a symlink, gitlink or absent path."""
    listing = git(repo, "ls-tree", "-z", d, "--", path).stdout
    meta, _, _ = listing.partition(b"\t")
    fields = meta.decode("ascii", errors="replace").split(" ")
    if len(fields) != 3 or fields[0] not in ("100644", "100755") or fields[1] != "blob":
        return None
    return git(repo, "show", f"{d}:{path}").stdout


def _plain_relative(path: str) -> bool:
    return (not path.startswith(("/", "-")) and not any(c in path for c in "$*?[]{}`~\\")
            and ".." not in path.split("/"))


def compute_exposure(profile: Profile, lock: LockSpec, consumer: Consumer, scan: TreeScan) -> Exposure:
    level = Level.CORE
    reasons: list[str] = []

    def raise_to(new: Level, why: str) -> None:
        nonlocal level
        if new > level:
            level = new
        reasons.append(f"{new.name.lower()}: {why}")

    if php_active(profile) or lock.extras in ("php", "magento"):
        raise_to(Level.PHP, "php profile" if php_active(profile) else f"guard.lock EXTRAS={lock.extras}")
    if magento_active(profile) or lock.extras == "magento":
        raise_to(Level.MAGENTO, "magento framework" if magento_active(profile) else "guard.lock EXTRAS=magento")
    if profile.status == "unparseable":
        raise_to(Level.MAGENTO, f"config unparseable ({profile.reason})")
    for surface in sorted(consumer.surfaces):
        raise_to(_LEVEL_OF[surface], f"consumers.toml surfaces includes {surface}")
    for found in sorted(scan.levels):
        raise_to(found, "tree scan: " + "; ".join(scan.evidence))
    return Exposure(level, tuple(reasons), scan)
