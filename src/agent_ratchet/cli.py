"""`agent-ratchet` command line: scan, baseline-integrity and version subcommands."""

from __future__ import annotations

import argparse
import sys

from agent_ratchet import ai_slop_scanner, migrate, test_baseline_integrity
from agent_ratchet.version import VERSION, installed_sha

EXIT_SHA_MISMATCH = 3


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agent-ratchet", description="Shared quality and refactoring guards.", add_help=False, allow_abbrev=False)
    parser.add_argument("--expect-sha", default=None, help="Fail with exit 3 unless the installed commit equals this SHA")
    parser.add_argument("subcommand", choices=("scan", "baseline-integrity", "version", "migrate-imports"))
    return parser


def _fail_sha(installed: str | None, expected: str | None) -> int:
    print(f"agent-ratchet: installed {installed} != lock {expected}", file=sys.stderr)
    return EXIT_SHA_MISMATCH


def _version(rest: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="agent-ratchet version")
    parser.add_argument("--sha", action="store_true", help="Print the installed commit SHA instead of the version")
    args = parser.parse_args(rest)
    if not args.sha:
        print(VERSION)
        return 0
    sha = installed_sha()
    if sha is None:
        print("agent-ratchet: installed commit SHA unavailable (not a VCS install)", file=sys.stderr)
        return EXIT_SHA_MISMATCH
    print(sha)
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if sum(1 for a in argv if a == "--expect-sha" or a.startswith("--expect-sha=")) > 1:
        print("agent-ratchet: --expect-sha given more than once", file=sys.stderr)
        return EXIT_SHA_MISMATCH
    args, rest = _build_parser().parse_known_args(argv)
    if args.expect_sha is not None:
        sha = installed_sha()
        if sha is None or sha != args.expect_sha:
            return _fail_sha(sha, args.expect_sha)
    if args.subcommand == "scan":
        return ai_slop_scanner.main(rest)
    if args.subcommand == "baseline-integrity":
        return test_baseline_integrity.main(rest)
    if args.subcommand == "migrate-imports":
        return migrate.main(rest)
    return _version(rest)

