#!/usr/bin/env python3
"""Differential acceptance: guard-core findings must equal the legacy vendored guard's, case by case.

Materialises a throwaway local clone of a consumer at `--legacy-ref`, runs each case with the legacy
in-repo scripts and with guard-core, and compares (rc, stdout, stderr) after minimal normalisation.
Stdlib only; lives outside the installed package.
"""

from __future__ import annotations

import argparse
import difflib
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile

EXIT_OK, EXIT_DIFF, EXIT_USAGE = 0, 1, 2
LEGACY_SCRIPTS = {"scan": "scripts/audit/ai_slop_scanner.py", "baseline-integrity": "scripts/audit/test_baseline_integrity.py"}
_PROG_RE = re.compile(r"(?<![\w./-])(?:ai_slop_scanner\.py|test_baseline_integrity\.py|guard-core)(?![\w-])")


class CaseError(Exception):
    """A case could not be run to completion; always counts as a difference."""


def normalise(text: str, root: Path, tmp_dirs: list[str] | tuple[str, ...] = ()) -> str:
    """Only three rewrites, all literal: clone path -> <ROOT>, temp dirs this run created -> <TMP>, program names -> <PROG>."""
    for variant in {str(root), os.path.realpath(root)}:
        text = text.replace(variant, "<ROOT>")
    for tmp in sorted({d for t in tmp_dirs for d in (str(t), os.path.realpath(t))}, key=len, reverse=True):
        text = text.replace(tmp, "<TMP>")
    return _PROG_RE.sub("<PROG>", text)


def build_cases(commits: int, extra_scan_args: list[str]) -> list[tuple[str, str, list[str]]]:
    rng = f"HEAD~{commits}..HEAD"
    cases = [
        ("scan-staged-only", "scan", ["--staged-only"]),
        ("scan-commit-range", "scan", ["--commit-range", rng]),
        ("baseline-isolation", "baseline-integrity", ["--enforce-policy-isolation"]),
        ("baseline-require-base-ref", "baseline-integrity", ["--require-base-ref", "--enforce-policy-isolation", "--commit-range", rng]),
    ]
    for i, extra in enumerate(extra_scan_args, 1):
        cases.append((f"scan-extra-{i}", "scan", shlex.split(extra)))
    return cases


def _command(side: str, sub: str, args: list[str], opts: argparse.Namespace, clone: Path) -> list[str]:
    override = opts.legacy_cmd if side == "legacy" else opts.new_cmd
    if override:
        return [*shlex.split(override), sub, *args]
    if side == "legacy":
        script = LEGACY_SCRIPTS[sub]
        if not (clone / script).is_file():
            raise CaseError(f"legacy script missing at {opts.legacy_ref}: {script}")
        return ["python3", script, *args]
    return ["uvx", "--from", opts.new_from, "guard-core", "--expect-sha", opts.guard_sha, sub, *args]


def run_side(side: str, sub: str, args: list[str], opts: argparse.Namespace, clone: Path) -> tuple[int, str, str]:
    cmd = _command(side, sub, args, opts, clone)
    try:
        proc = subprocess.run(cmd, cwd=clone, capture_output=True, text=True, timeout=opts.timeout, errors="replace")
    except subprocess.TimeoutExpired as exc:
        raise CaseError(f"{side} timed out after {exc.timeout}s") from exc
    except OSError as exc:
        raise CaseError(f"{side} could not start {cmd[0]}: {exc}") from exc
    return proc.returncode, normalise(proc.stdout, clone, [clone.parent]), normalise(proc.stderr, clone, [clone.parent])


def _render(result: tuple[int, str, str] | CaseError) -> list[str]:
    if isinstance(result, CaseError):
        return [f"ERROR: {result}\n"]
    rc, out, err = result
    return [f"rc: {rc}\n", "--- stdout ---\n", *out.splitlines(keepends=True), "\n--- stderr ---\n", *err.splitlines(keepends=True), "\n"]


def run_case(sub: str, args: list[str], opts: argparse.Namespace, clone: Path) -> tuple[bool, str]:
    results: dict[str, tuple[int, str, str] | CaseError] = {}
    for side in ("legacy", "new"):
        try:
            results[side] = run_side(side, sub, args, opts, clone)
        except CaseError as exc:
            results[side] = exc
    errored = any(isinstance(r, CaseError) for r in results.values())
    if not errored and results["legacy"] == results["new"]:
        return True, ""
    diff = difflib.unified_diff(_render(results["legacy"]), _render(results["new"]), "legacy", "new")
    return False, "".join(diff) or "ERROR: both sides failed identically\n"


def _inside_git_repo(path: Path) -> bool:
    probe = path.resolve()
    while not probe.exists():
        probe = probe.parent
    return subprocess.run(["git", "-C", str(probe), "rev-parse"], capture_output=True).returncode == 0


def _git(*args: str) -> None:
    subprocess.run(["git", *args], check=True, capture_output=True, text=True)


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--consumer", required=True, type=Path, help="Path of the consumer git checkout (never modified)")
    p.add_argument("--legacy-ref", required=True, help="Consumer commit holding the vendored legacy guard")
    p.add_argument("--guard-sha", required=True, help="guard-core commit under test")
    p.add_argument("--commits", type=int, default=30, help="N in HEAD~N..HEAD for the range cases")
    p.add_argument("--out", required=True, type=Path, help="Report directory, must be outside any git repository")
    p.add_argument("--new-from", default=None, help="uvx --from spec (default: public GitHub URL at --guard-sha)")
    p.add_argument("--extra-scan-args", action="append", default=[], help="Extra `scan` case, e.g. 'src test'; repeatable")
    p.add_argument("--timeout", type=float, default=600.0, help="Per-command timeout in seconds")
    p.add_argument("--legacy-cmd", default=None, help="Test seam: command prefix replacing the legacy script")
    p.add_argument("--new-cmd", default=None, help="Test seam: command prefix replacing uvx guard-core")
    opts = p.parse_args(argv)
    opts.new_from = opts.new_from or f"git+https://github.com/dpopek/guard-core@{opts.guard_sha}"
    return opts


def main(argv: list[str] | None = None) -> int:
    opts = parse_args(sys.argv[1:] if argv is None else argv)
    if _inside_git_repo(opts.out):
        print(f"differential: refusing --out inside a git repository: {opts.out}", file=sys.stderr)
        return EXIT_USAGE
    resolved = subprocess.run(["git", "-C", str(opts.consumer), "rev-parse", "--verify", "--quiet", f"{opts.legacy_ref}^{{commit}}"], capture_output=True, text=True)
    if resolved.returncode != 0:
        print(f"differential: --legacy-ref {opts.legacy_ref!r} does not resolve to a commit in {opts.consumer}", file=sys.stderr)
        return EXIT_USAGE
    legacy_sha = resolved.stdout.strip()
    tmp = Path(tempfile.mkdtemp(prefix="guard-diff-"))
    try:
        clone = tmp / "clone"
        try:
            _git("clone", "--quiet", "--no-hardlinks", str(opts.consumer), str(clone))
            _git("-C", str(clone), "checkout", "--quiet", "--detach", legacy_sha)
        except subprocess.CalledProcessError as exc:
            print(f"differential: cannot materialise consumer: {exc.stderr.strip()}", file=sys.stderr)
            return EXIT_USAGE
        opts.out.mkdir(parents=True, exist_ok=True)
        for stale in opts.out.glob("*.diff"):
            stale.unlink()
        lines, failed = [f"legacy-ref: {legacy_sha}"], 0
        for name, sub, args in build_cases(opts.commits, opts.extra_scan_args):
            same, diff = run_case(sub, args, opts, clone)
            lines.append(f"{'IDENTICAL' if same else 'DIFFERENT'} {name}: {sub} {' '.join(args)}")
            if not same:
                failed += 1
                (opts.out / f"{name}.diff").write_text(diff, encoding="utf-8")
        lines.append(f"{failed} differing case(s)")
        (opts.out / "summary.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
        print("\n".join(lines))
        return EXIT_DIFF if failed else EXIT_OK
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
