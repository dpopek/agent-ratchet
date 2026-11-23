"""`guard-fleet`: parse, check the launcher's sha, load config, refresh the mirror, self-check, dispatch (spec 6.12)."""

from __future__ import annotations

import argparse
import shlex
import sys
from collections.abc import Sequence

from .cleanup import run_cleanup
from .config import load_config
from .deps import Deps, default_deps
from .env import take_lock_update_flag
from .exits import Cancelled, FleetExit, NoHelper, ShaMismatch, UsageError
from .gh import GhAuthError, GhNetworkError
from .git import GitNetworkError
from .locks import RunLock
from .mirror import mirror_readonly, refresh_mirror
from .plan import _clients, run_plan
from .release import Options, network_kind, resume_command, run_land, run_release
from .report import render_plan
from .selfcheck import check_expect_sha, installed_sha, self_check
from .selfpin import run_self_pin
from .status import run_status
from .venvs import run_venvs


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="guard-fleet", description="Roll agent-ratchet releases across consumers.")
    p.add_argument("--expect-sha", required=True, help="commit the launcher expects this install to be")
    sub = p.add_subparsers(dest="command")
    sub.add_parser("status", help="read-only fleet overview")
    plan = sub.add_parser("plan", help="what a release would do (read only)")
    plan.add_argument("tag", nargs="?")
    plan.add_argument("--only", nargs="+", default=[], metavar="S")
    plan.add_argument("--include-unexposed", action="store_true")
    release = sub.add_parser("release", help="roll, confirm once, land ring 1 then ring 2")
    release.add_argument("tag")
    release.add_argument("--only", nargs="+", default=[], metavar="S")
    release.add_argument("--include-unexposed", action="store_true")
    release.add_argument("--rebuild", nargs="+", default=[], metavar="S")
    release.add_argument("--diff", action="store_true")
    release.add_argument("--hold-ring-2", action="store_true")
    land = sub.add_parser("land", help="resume a stopped run or land the held ring 2")
    land.add_argument("tag")
    land.add_argument("--ring", type=int, choices=(1, 2))
    land.add_argument("--rebuild", nargs="+", default=[], metavar="S")
    cleanup = sub.add_parser("cleanup", help="remove the fleet's merged leftovers")
    cleanup.add_argument("tag", nargs="?")
    cleanup.add_argument("--remote", action="store_true")
    selfpin = sub.add_parser("self-pin", help="pin the launcher to a release")
    selfpin.add_argument("tag")
    venvs = sub.add_parser("venvs", help="report (or --refresh) the consumers' virtualenvs")
    venvs.add_argument("--refresh", action="store_true")
    venvs.add_argument("--only", nargs="+", default=[], metavar="S")
    return p


def _typed(argv: Sequence[str]) -> str:
    """The command as the operator typed it: the launcher prepends `--expect-sha <sha>`, which is dropped."""
    rest, skip = [], False
    for i, arg in enumerate(argv):
        if skip:
            skip = False
            continue
        if arg == "--expect-sha":
            skip = i + 1 < len(argv)
            continue
        if arg.startswith("--expect-sha="):
            continue
        rest.append(arg)
    return shlex.join(["guard-fleet", *rest])


def _options(args: argparse.Namespace) -> Options:
    return Options(tag=args.tag, only=tuple(getattr(args, "only", ())), include_unexposed=getattr(
        args, "include_unexposed", False), rebuild=tuple(args.rebuild), diff=getattr(args, "diff", False),
        hold_ring_2=getattr(args, "hold_ring_2", False),
        rings=(args.ring,) if getattr(args, "ring", None) else ())


def _dispatch(deps: Deps, args: argparse.Namespace, *, lock_update: bool, running: str, typed: str) -> int:
    cfg = load_config(deps.dirs.consumers_toml, home=deps.dirs.home)
    git, _ = _clients(deps)
    lock = RunLock(deps.dirs.run_lock)
    if lock.acquire(exclusive=False):   # nobody mutates: refresh; else read the mirror as it is
        try:
            mirror = refresh_mirror(deps, git)
        finally:
            lock.release()
    else:
        mirror, _ = mirror_readonly(deps)
    self_check(git, mirror, running, target_sha=None)
    cmd = args.command
    if cmd == "status":
        return run_status(deps, cfg)
    if cmd == "plan":
        res = run_plan(deps, cfg, args.tag, only=tuple(args.only), include_unexposed=args.include_unexposed)
        deps.out.write(render_plan(res))
        return int(res.exit)
    if cmd == "release":
        return int(run_release(deps, cfg, _options(args), lock_update=lock_update, running_sha=running, typed=typed))
    if cmd == "land":
        return int(run_land(deps, cfg, _options(args), lock_update=lock_update, running_sha=running, typed=typed))
    if cmd == "cleanup":
        return int(run_cleanup(deps, cfg, args.tag, remote=args.remote))
    if cmd == "self-pin":
        return int(run_self_pin(deps, git, args.tag))
    return int(run_venvs(deps, cfg, refresh=args.refresh, only=tuple(args.only)))


def main(argv: Sequence[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        args = _parser().parse_args(argv)
    except SystemExit as exc:   # --help: 0; any argparse error: 2
        return exc.code if isinstance(exc.code, int) else 2
    if args.command is None:
        _parser().print_usage(sys.stderr)
        return int(FleetExit.USAGE)
    deps = default_deps()
    lock_update = take_lock_update_flag(deps.environ)   # read once, popped: only C2 ever sees it
    typed = _typed(argv)
    try:
        running = installed_sha()
        check_expect_sha(args.expect_sha, running)
        assert running is not None   # check_expect_sha refused None
        return _dispatch(deps, args, lock_update=lock_update, running=running, typed=typed)
    except UsageError as exc:
        deps.err.write(f"{exc}\n")
        return int(FleetExit.USAGE)
    except ShaMismatch as exc:
        deps.err.write(f"{exc}\n")
        return int(FleetExit.SHA_MISMATCH)
    except Cancelled as exc:
        deps.err.write(f"cancelled: {exc}\n")
        return int(FleetExit.CANCELLED)
    except NoHelper as exc:
        deps.err.write(f"no confirmation helper: {exc}\n")
        return int(FleetExit.NO_HELPER)
    except (GhAuthError, GhNetworkError, GitNetworkError) as exc:
        tag = getattr(args, "tag", None)
        if args.command in ("release", "land") and tag:
            nxt = f"Resume: {resume_command(tag)}"
        else:
            nxt = f"Rerun: {typed}"
        deps.err.write(f"{network_kind(exc)}: {exc}\n{nxt}\n")
        return int(FleetExit.CANCELLED)
