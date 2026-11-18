"""`agent-ratchet migrate-imports`: move consumer code off the removed ``guard_core`` package.

Only import statements are rewritten. Runtime strings and other mentions are reported.
"""

from __future__ import annotations

import argparse
import ast
import bisect
import os
import re
import shutil
import sys
import tempfile
import tokenize
from dataclasses import dataclass, field
from typing import Literal

from agent_ratchet.ast_safety import GuardAnalysisError, parse_python

Kind = Literal["rewrite", "manual-import", "manual-runtime", "mention"]

OLD = "guard_core"
NEW = "agent_ratchet"
ROOTS = (OLD, NEW)
SKIP_DIRS = frozenset({".git", ".venv", "venv", "node_modules", "__pycache__"})
MANUAL_NAMES = frozenset({"SELF_SKIP_NAMES", "RELEASE_TAG_PATTERN", "GUARD_TEST_NAMES"})
_KIND_ORDER = {"rewrite": 0, "manual-import": 1, "manual-runtime": 2, "mention": 3}
_BOM = "﻿"
_LINE_RE = re.compile(r"[^\r\n]*(?:\r\n|\r|\n)|[^\r\n]+")
_RUNTIME_RE = re.compile(
    r"\A(?:guard_core|guard-core)\Z"
    r"|\Aguard_core\.\w"
    r"|\Aguard-core(?=[\s=<>!~@\[(;])"
    r"|(?<![\w-])-m\s*guard_core(?!\w)"
)
_INSIGNIFICANT = frozenset({tokenize.COMMENT, tokenize.NL, tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT, tokenize.ENDMARKER})


@dataclass(frozen=True)
class Item:
    path: str
    line: int
    kind: Kind
    text: str


@dataclass
class FilePlan:
    new_source: str
    items: list[Item] = field(default_factory=list)


def _is_runtime_string(value: str) -> bool:
    return _RUNTIME_RE.search(value) is not None


def _in_roots(module: str | None) -> bool:
    return module is not None and any(module == r or module.startswith(r + ".") for r in ROOTS)


def _guard_version_target(module: str) -> str | None:
    last = module.rsplit(".", 1)[-1]
    if last == "version":
        return "VERSION"
    if last in ("refactoring_guard", "git_guard_io"):
        return "RULES_VERSION"
    return None


def _char_col(line: str, byte_col: int) -> int:
    return len(line.encode("utf-8")[:byte_col].decode("utf-8", errors="ignore"))


def plan_file(source: str, path: str) -> FilePlan:
    """Plan the rewrite of one decoded file; raises ``SyntaxError``/``ValueError`` when it cannot be parsed."""
    bom = source.startswith(_BOM)
    text = source[1:] if bom else source
    lines = _LINE_RE.findall(text)
    tree = parse_python(text, path)
    tokens = [t for t in tokenize.generate_tokens(iter(lines).__next__) if t.type not in _INSIGNIFICANT]
    starts = [t.start for t in tokens]

    def first_line(row: int) -> str:
        return lines[row - 1].strip()

    def pos(row: int, byte_col: int) -> tuple[int, int]:
        return row, _char_col(lines[row - 1], byte_col)

    def token_at(p: tuple[int, int]) -> tokenize.TokenInfo | None:
        i = bisect.bisect_left(starts, p)
        return tokens[i] if i < len(starts) and starts[i] == p else None

    edits: list[tuple[int, int, int, str]] = []
    items: dict[tuple[int, Kind], Item] = {}
    reported: set[int] = set()

    def report(row: int, kind: Kind) -> None:
        items.setdefault((row, kind), Item(path, row, kind, first_line(row)))
        reported.add(row)

    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.level == 0 and _in_roots(node.module):
            _plan_from(node, edits, report, pos, tokens, starts)
        elif isinstance(node, ast.Import):
            _plan_import(node, edits, report, pos, token_at)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str) and _is_runtime_string(node.value):
            report(node.lineno, "manual-runtime")

    rows = {e[0] for e in edits}
    for row, c0, c1, repl in sorted(edits, reverse=True):
        line = lines[row - 1]
        lines[row - 1] = line[:c0] + repl + line[c1:]
    new_text = "".join(lines)
    reported |= rows
    for n, line in enumerate(_LINE_RE.findall(new_text), start=1):
        if n not in reported and ("guard_core" in line or "guard-core" in line):
            items[(n, "mention")] = Item(path, n, "mention", line.strip())
    ordered = sorted(items.values(), key=lambda i: (i.line, _KIND_ORDER[i.kind]))
    return FilePlan((_BOM if bom else "") + new_text, ordered)


def _plan_from(node: ast.ImportFrom, edits, report, pos, tokens, starts) -> None:
    assert node.module is not None
    names = {a.name for a in node.names}
    if names & MANUAL_NAMES:
        report(node.lineno, "manual-import")
        return
    local: list[tuple[int, int, int, str]] = []
    start = bisect.bisect_left(starts, pos(node.lineno, node.col_offset))
    # tokens[start] is "from"; the next token is the first segment of the module path.
    mod_tok = tokens[start + 1]
    if node.module.split(".")[0] == OLD and mod_tok.string == OLD:
        local.append((mod_tok.start[0], mod_tok.start[1], mod_tok.end[1], NEW))
    target = _guard_version_target(node.module)
    if target is not None:
        for alias in node.names:
            if alias.name != "GUARD_VERSION":
                continue
            row, col = pos(alias.lineno, alias.col_offset)
            repl = target if alias.asname else f"{target} as GUARD_VERSION"
            local.append((row, col, col + len("GUARD_VERSION"), repl))
    if local:
        edits.extend(local)
        report(node.lineno, "rewrite")


def _plan_import(node: ast.Import, edits, report, pos, token_at) -> None:
    changed = False
    for alias in node.names:
        if alias.name != OLD and not alias.name.startswith(OLD + "."):
            continue
        if alias.asname is None:
            report(node.lineno, "manual-import")
            continue
        row, col = pos(alias.lineno, alias.col_offset)
        tok = token_at((row, col))
        if tok is not None and tok.string == OLD:
            edits.append((row, col, tok.end[1], NEW))
            changed = True
    if changed:
        report(node.lineno, "rewrite")


def _iter_py_files(paths: list[str]):
    for given in paths:
        if os.path.isfile(given):
            if given.endswith(".py"):
                yield given.replace(os.sep, "/")
            continue
        for dirpath, dirnames, filenames in os.walk(given, followlinks=False):
            dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not os.path.islink(os.path.join(dirpath, d)))
            for name in sorted(filenames):
                full = os.path.join(dirpath, name)
                if name.endswith(".py") and not os.path.islink(full):
                    yield full.replace(os.sep, "/")


def _atomic_write(path: str, data: bytes) -> None:
    """Replace ``path`` with ``data`` via a same-directory temp file, keeping the original mode."""
    directory = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".migrate-", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        shutil.copymode(path, tmp)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agent-ratchet migrate-imports", description="Rewrite guard_core imports to agent_ratchet.")
    parser.add_argument("--write", action="store_true", help="Apply the rewrites (default: report only)")
    parser.add_argument("paths", nargs="*", default=["."], metavar="PATH")
    try:
        args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    paths = args.paths or ["."]
    missing = [p for p in paths if not os.path.exists(p)]
    for p in missing:
        print(f"agent-ratchet migrate-imports: no such path: {p}", file=sys.stderr)
    if missing:
        return 2
    errors = 0
    items: list[Item] = []
    seen: set[str] = set()
    for path in sorted(set(_iter_py_files(paths))):
        real = os.path.realpath(path)
        if real in seen:
            continue
        seen.add(real)
        try:
            with open(path, "rb") as fh:
                raw = fh.read()
            plan = plan_file(raw.decode("utf-8"), path)
        except (OSError, UnicodeDecodeError, SyntaxError, ValueError, GuardAnalysisError, RecursionError, tokenize.TokenError) as exc:
            reason = (str(exc).splitlines() or [type(exc).__name__])[0]
            print(f"{path}:0: error: {reason}")
            errors += 1
            continue
        items.extend(plan.items)
        new_raw = plan.new_source.encode("utf-8")
        if args.write and new_raw != raw:
            try:
                _atomic_write(real, new_raw)
            except OSError as exc:
                print(f"{path}:0: error: {(str(exc).splitlines() or [type(exc).__name__])[0]}")
                errors += 1
    items.sort(key=lambda i: (i.path, i.line, _KIND_ORDER[i.kind]))
    for it in items:
        print(f"{it.path}:{it.line}: {it.kind}: {it.text}")
    rewrites = sum(1 for i in items if i.kind == "rewrite")
    manual = sum(1 for i in items if i.kind in ("manual-import", "manual-runtime"))
    mentions = sum(1 for i in items if i.kind == "mention")
    print(f"agent-ratchet migrate-imports: {rewrites} rewrite(s), {manual} manual, {mentions} mention(s)")
    if errors:
        return 2
    if manual or (rewrites and not args.write):
        return 1
    return 0
