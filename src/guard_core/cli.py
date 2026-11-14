"""`guard-core` command line: scan, baseline-integrity and version subcommands."""

from __future__ import annotations

import argparse
import sys

from guard_core import ai_slop_scanner, test_baseline_integrity
from guard_core.version import GUARD_VERSION, installed_sha

EXIT_SHA_MISMATCH = 3


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="guard-core", description="Shared quality and refactoring guards.", add_help=False, allow_abbrev=False)
    parser.add_argument("--expect-sha", default=None, help="Fail with exit 3 unless the installed commit equals this SHA")
    parser.add_argument("subcommand", choices=("scan", "baseline-integrity", "version"))
    return parser


def _fail_sha(installed: str | None, expected: str | None) -> int:
    print(f"guard-core: installed {installed} != lock {expected}", file=sys.stderr)
    return EXIT_SHA_MISMATCH


def _version(rest: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="guard-core version")
    parser.add_argument("--sha", action="store_true", help="Print the installed commit SHA instead of the version")
    args = parser.parse_args(rest)
    if not args.sha:
        print(GUARD_VERSION)
        return 0
    sha = installed_sha()
    if sha is None:
        print("guard-core: installed commit SHA unavailable (not a VCS install)", file=sys.stderr)
        return EXIT_SHA_MISMATCH
    print(sha)
    return 0


def main(argv: list[str] | None = None) -> int:
    args, rest = _build_parser().parse_known_args(sys.argv[1:] if argv is None else argv)
    if args.expect_sha is not None:
        sha = installed_sha()
        if sha is None or sha != args.expect_sha:
            return _fail_sha(sha, args.expect_sha)
    if args.subcommand == "scan":
        return ai_slop_scanner.main(rest)
    if args.subcommand == "baseline-integrity":
        return test_baseline_integrity.main(rest)
    return _version(rest)
