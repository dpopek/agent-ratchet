"""Text and added-diff slop rules (regex, suppressors, shortcut escapes); no git-transition logic."""

from __future__ import annotations

import re
from typing import Any, Mapping, Sequence

from agent_ratchet.git_guard_io import CODE_SCAN_EXTS, NO_FIXTURES, SlopViolation, is_self_skipped, is_test_filename


CONVERSATIONAL_PATTERNS = [(
    re.compile(
        r"(?i)\b(as an ai language model|certainly[!,]|here is the implementation|"
        r"i hope this helps|let me know if you need anything else|here's the complete code|"
        r"in this updated version|sure thing[!,]|feel free to ask)\b"
    ),
    "conversational_marker", "AI conversational leftover / monologue marker detected",
)]

TAUTOLOGICAL_PATTERNS = [
    (re.compile(r"\bassert\s+(?:True|1\s*==\s*1|not\s+False)\b"), "tautological_assertion", "Tautological Python assertion detected (e.g. assert True or assert 1 == 1)"),
    (re.compile(r"expect\(\s*(?:true\s*\)\.toBe\(\s*true|1\s*\)\.toBe\(\s*1|false\s*\)\.toBe\(\s*false|true\s*\)\.toBeTruthy\(\s*)\)"), "tautological_assertion", "Tautological Jest/Vitest assertion detected (e.g. expect(true).toBe(true))"),
    (re.compile(r"def\s+test_[a-zA-Z0-9_]+\s*\([^)]*\)\s*:\s*(?:pass|\.\.\.)(?:\s*#.*)?$", re.MULTILINE), "empty_dummy_test", "Empty dummy test body with only pass / ... detected"),
    (
        re.compile(
            r"\b(?:it|test)(?:\s*\.each\s*\([^)]*\))?\s*\(\s*(['\"`]).*?\1\s*,\s*"
            r"(?:async\s+)?(?:function\b\s*\([^)]*\)|(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>)\s*"
            r"\{\s*(?://[^\n]*\s*|/\*[\s\S]*?\*/\s*)*\}"
        ),
        "empty_dummy_test", "Empty JS/TS test block with no assertions detected",
    ),
]

ANTI_HACK_PATTERNS = [(
    re.compile(r"get\s+[a-zA-Z0-9_$]+\s*\(\)\s*\{\s*throw\b"),
    "synthetic_throwing_getter",
    "Synthetic throwing getter detected in test input! Test authentic I/O or malformed payloads instead of breaking prototype getters.",
)]

SKIP_ESCAPE_RE = re.compile(
    r"(?:@pytest\.mark\.(?:skip|xfail)\b|\bpytest\.(?:skip|xfail)\s*\(|@unittest\.skip\b|"
    r"\b(?:it|test|describe)\.(?:skip|only|todo)\s*\(|\b(?:xit|xdescribe)\s*\()"
)

TS_NOCHECK_RE = re.compile(r"@ts-nocheck\b")

SUPPRESSOR_DETECT_RE = re.compile(
    r"(?:#\s*noqa\b|#\s*type:\s*ignore\b|@ts-ignore\b|@ts-expect-error\b|eslint-disable(?:-next-line|-line)?\b)"
)

JUSTIFIED_SUPPRESSOR_PATTERNS = [
    re.compile(r"#\s*noqa:\s*[A-Z0-9,\s]+\s+--\s+\S.{4,}"),
    re.compile(r"#\s*type:\s*ignore\[[a-zA-Z0-9_,\s-]+\]\s+--\s+\S.{4,}"),
    re.compile(r"@ts-(?:ignore|expect-error)(?:\s+TS\d+)?\s+--\s+\S.{7,}"),
    re.compile(r"eslint-disable(?:-next-line|-line)?\s+[a-zA-Z0-9_/@,\s-]+\s+--\s+\S.{4,}"),
]

TASK_NOMENCLATURE_RE: re.Pattern[str] = re.compile(
    r"(?i)(?<![a-z0-9])(?:wave[_\s-]*\d+|phase[_\s-]*\d+[a-z]?|def-\d+|fix_v\d+|v\d+_final|path_[ab]_audit)(?![a-z0-9])"
)

EVASION_COMMENT_RE: re.Pattern[str] = re.compile(
    r"(?i)(?:without calling the forbidden|"
    r"bypass(?:ing)?\s+(?:the\s+)?(?:ratchet|ceiling|(?:loc|complexity|size)\s+limit|"
    r"(?:architecture|architectural|boundary)\s+(?:guard|rule|test)|lint(?:er)?)|"
    r"avoid\s+circular\s+import|alias\s+for\s+backward\s+compatibility)"
)


def _scan_extra_rules(
    lines: list[str],
    filename: str,
    is_test: bool,
    extra_rules: Sequence[Mapping[str, Any]],
) -> list[SlopViolation]:
    out: list[SlopViolation] = []
    for rule in extra_rules:
        if rule.get("test_only", False) and not is_test:
            continue
        pat = re.compile(str(rule["pattern"]))
        for lineno, line in enumerate(lines, 1):
            if pat.search(line):
                out.append(SlopViolation(filename, lineno, str(rule["category"]), str(rule["message"]), line.strip()[:100]))
    return out


def _scan_code_specific_slop(
    text: str,
    lines: list[str],
    filename: str,
    extra_rules: Sequence[Mapping[str, Any]],
) -> list[SlopViolation]:
    violations: list[SlopViolation] = []
    is_test = is_test_filename(filename)
    for lineno, line in enumerate(lines, 1):
        if TS_NOCHECK_RE.search(line):
            violations.append(SlopViolation(filename, lineno, "unjustified_lint_escape", "File-wide @ts-nocheck is forbidden; fix types locally.", line.strip()[:100]))
        for pattern, category, message in TAUTOLOGICAL_PATTERNS:
            if category == "tautological_assertion" and pattern.search(line):
                violations.append(SlopViolation(filename, lineno, category, message, line.strip()[:100]))
    if is_test or filename.endswith(".py"):
        for pattern, category, message in TAUTOLOGICAL_PATTERNS:
            if category == "empty_dummy_test":
                for match in pattern.finditer(text):
                    lineno = text[: match.start()].count("\n") + 1
                    violations.append(SlopViolation(filename, lineno, category, message, match.group(0).strip()[:100]))
    if is_test:
        for pattern, category, message in ANTI_HACK_PATTERNS:
            for match in pattern.finditer(text):
                lineno = text[: match.start()].count("\n") + 1
                snip = match.group(0).strip().replace("\n", " ")[:100]
                violations.append(SlopViolation(filename, lineno, category, message, snip))
    violations.extend(_scan_extra_rules(lines, filename, is_test, extra_rules))
    return violations


def scan_text_for_slop(text: str, filename: str, extra_rules: Sequence[Mapping[str, Any]] = ()) -> list[SlopViolation]:
    violations: list[SlopViolation] = []
    lines = text.splitlines()
    for lineno, line in enumerate(lines, 1):
        for pattern, category, message in CONVERSATIONAL_PATTERNS:
            if pattern.search(line):
                violations.append(SlopViolation(filename, lineno, category, message, line.strip()[:100]))
        if EVASION_COMMENT_RE.search(line):
            violations.append(SlopViolation(filename, lineno, "guard_evasion_comment", "Comment explicitly admits bypassing architectural/ratchet guard (Zero-S2/S6).", line.strip()[:100]))
    if filename.endswith(CODE_SCAN_EXTS):
        violations.extend(_scan_code_specific_slop(text, lines, filename, extra_rules))
    return violations


def _is_justified_suppressor(line: str) -> bool:
    return any(p.search(line) for p in JUSTIFIED_SUPPRESSOR_PATTERNS)


def _check_added_diff_line(current_file: str, lineno: int, added_line: str) -> list[SlopViolation]:
    out: list[SlopViolation] = []
    snip = added_line.strip()[:100]
    if SKIP_ESCAPE_RE.search(added_line):
        out.append(SlopViolation(current_file, lineno, "test_skip_escape", "Forbidden test skip/xfail/only added in diff! Fix the underlying issue.", snip))
    if TS_NOCHECK_RE.search(added_line):
        out.append(SlopViolation(current_file, lineno, "unjustified_lint_escape", "File-wide @ts-nocheck is forbidden; fix types locally.", snip))
    elif SUPPRESSOR_DETECT_RE.search(added_line) and not _is_justified_suppressor(added_line):
        out.append(SlopViolation(current_file, lineno, "unjustified_lint_escape", "Suppressor directive requires explicit rule code and '-- <reason>'.", snip))
    if TASK_NOMENCLATURE_RE.search(added_line):
        out.append(SlopViolation(current_file, lineno, "task_nomenclature_leak", "Task/session nomenclature (Wave, Phase, DEF-xxx, fix_v2) is forbidden in code/comments (Zero-S5).", snip))
    if EVASION_COMMENT_RE.search(added_line):
        out.append(SlopViolation(current_file, lineno, "guard_evasion_comment", "Comment explicitly admits bypassing architectural/ratchet guard (Zero-S2/S6).", snip))
    return out


def scan_diff_for_shortcut_escapes(diff_text: str, *, fixture_paths: frozenset[str] = NO_FIXTURES) -> list[SlopViolation]:
    violations: list[SlopViolation] = []
    current_file, lineno = "", 0
    for raw_line in diff_text.splitlines():
        if raw_line.startswith("+++ b/"):
            current_file, lineno = raw_line[6:].strip(), 0
        elif raw_line.startswith("@@ "):
            m = re.search(r"\+(\d+)", raw_line)
            lineno = int(m.group(1)) - 1 if m else 0
        elif not current_file or is_self_skipped(current_file, fixture_paths=fixture_paths) or not current_file.endswith(CODE_SCAN_EXTS):
            continue
        elif raw_line.startswith("+") and not raw_line.startswith("+++"):
            lineno += 1
            violations.extend(_check_added_diff_line(current_file, lineno, raw_line[1:]))
        elif not raw_line.startswith("-"):
            lineno += 1
    return violations
