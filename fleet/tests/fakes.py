"""Test doubles: a routed runner, a controllable clock and a deps factory."""

from __future__ import annotations

import io
import json
import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping, Sequence

from guard_fleet import proc
from guard_fleet.env import base_child_env
from guard_fleet.git import Git
from guard_fleet.deps import ConfirmResult, Deps
from guard_fleet.dirs import Dirs
from guard_fleet.proc import Result


@dataclass
class Route:
    match: tuple[str, ...] | Callable[[tuple[str, ...]], bool]
    rc: int = 0
    stdout: bytes = b""
    stderr: bytes = b""
    effect: Callable[[tuple[str, ...], Path, Mapping[str, str]], Result | None] | None = None

    def matches(self, argv: tuple[str, ...]) -> bool:
        if callable(self.match):
            return bool(self.match(argv))
        return argv[: len(self.match)] == self.match


class FakeRunner:
    def __init__(self, routes: list[Route], real: frozenset[str] = frozenset({"git"})) -> None:
        self.routes = routes
        self.real = real
        self.calls: list[tuple[tuple[str, ...], Path, dict[str, str]]] = []

    def __call__(self, argv: Sequence[str], *, cwd: Path, env: Mapping[str, str], timeout: float,
                 input: bytes | None = None, log: Path | None = None) -> Result:
        args = tuple(argv)
        prefix = proc.low_priority_prefix()
        for p in (prefix, ("nice", "-n", "15")):
            if p and args[: len(p)] == p:
                args = args[len(p):]
                break
        self.calls.append((args, cwd, dict(env)))
        if args and args[0] in self.real:
            return proc.run(args, cwd=cwd, env=env, timeout=timeout, input=input, log=log)
        for route in self.routes:
            if route.matches(args):
                if route.effect is not None:
                    got = route.effect(args, cwd, env)
                    if got is not None:
                        return got
                return Result(args, route.rc, route.stdout, route.stderr, False)
        raise AssertionError(f"unrouted argv: {args!r}")


class FakeClock:
    def __init__(self, start_mono: float = 1000.0, start_wall: float = 1_700_000_000.0) -> None:
        self._mono = start_mono
        self._wall = start_wall

    def monotonic(self) -> float:
        return self._mono

    def wall(self) -> float:
        return self._wall

    def advance(self, seconds: float, *, wall_only: bool = False) -> None:
        self._wall += seconds
        if not wall_only:
            self._mono += seconds


def make_deps(tmp_home: Path, routes=(), confirm=None, environ=None) -> Deps:
    clock = FakeClock()
    return Deps(
        run=FakeRunner(list(routes)),
        confirm=confirm or (lambda _reason: ConfirmResult("approved", "")),
        clock=clock,
        sleep=clock.advance,
        environ=dict(os.environ) if environ is None else environ,
        dirs=Dirs(tmp_home),
        out=io.StringIO(),
        err=io.StringIO(),
        platform="linux",
    )


class FakeConfirm:
    """Returns the next scripted status as a ConfirmResult and records each reason."""

    def __init__(self, results: Sequence[str]) -> None:
        self._results = list(results)
        self.reasons: list[str] = []

    def __call__(self, reason: str) -> ConfirmResult:
        self.reasons.append(reason)
        status = self._results.pop(0)
        return ConfirmResult(status, f"detail-{status}")  # type: ignore[arg-type]


def real_git() -> Git:
    """A Git over the real subprocess seam, with the test's clean environment."""
    return Git(proc.run, base_child_env(os.environ, tool_bin=Path("/nonexistent")), lambda s: None)


_FORBIDDEN_GH_FLAGS = frozenset({"--admin", "--auto", "--squash", "--rebase", "-d", "--delete-branch", "--draft"})


def _http(status: int, body: bytes = b"", headers: Mapping[str, str] | None = None) -> Result:
    head = "".join(f"{k}: {v}\r\n" for k, v in (headers or {}).items())
    out = f"HTTP/2.0 {status} X\r\n{head}\r\n".encode() + body
    return Result((), 0 if status < 400 else 1, out, b"", False)


def _flag(args: Sequence[str], name: str) -> str | None:
    return args[args.index(name) + 1] if name in args else None


class FakeGh:
    """A `gh` stand-in backed by real bare repositories; tests seed prs, runs, jobs and annotations."""

    def __init__(self, bares: Mapping[str, Path], login: str = "operator") -> None:
        self.bares = dict(bares)
        self.login = login
        self.argvs: list[tuple[str, ...]] = []
        self.prs: dict[str, list[dict]] = {}
        self.runs: dict[str, list[dict]] = {}
        self.jobs: dict[int, dict] = {}
        self.annotations: dict[int, list[dict]] = {}
        self.workflows: dict[tuple[str, str], str] = {}
        self.merge_commit_allowed: dict[str, bool] = {}
        self.closed_comments: dict[tuple[str, int], str] = {}

    def route(self) -> Route:
        return Route(match=lambda argv: argv[:1] == ("gh",), effect=self)

    # -- dispatch ------------------------------------------------------------

    def __call__(self, argv: tuple[str, ...], cwd: Path, env: Mapping[str, str]) -> Result:
        self.argvs.append(argv)
        bad = _FORBIDDEN_GH_FLAGS.intersection(argv)
        assert not bad, f"forbidden gh flag(s) {sorted(bad)}: {argv!r}"
        assert argv[1:3] != ("pr", "checks"), f"forbidden gh command: {argv!r}"
        if argv[1] == "api":
            return self._api(argv, env)
        slug = _flag(argv, "--repo")
        assert slug is not None, f"gh call without --repo: {argv!r}"
        handler = getattr(self, "_" + "_".join(argv[1:3]), None)
        assert handler is not None, f"unrouted gh command: {argv!r}"
        return handler(argv, slug, env)

    # -- api -----------------------------------------------------------------

    def _git(self, bare: Path, *args: str, env: Mapping[str, str]) -> Result:
        return proc.run(("git", "--git-dir", str(bare), *args), cwd=bare, env=env, timeout=30)

    def _api(self, argv: tuple[str, ...], env: Mapping[str, str]) -> Result:
        path = argv[-1]
        if path == "user":
            return _http(200, json.dumps({"login": self.login}).encode())
        m = re.fullmatch(r"repos/([^/]+/[^/]+)(?:/(.*))?", path)
        assert m, f"gh api path must start with repos/ or be user: {path!r}"
        slug, rest = m.group(1), m.group(2) or ""
        bare = self.bares.get(slug)
        if bare is None:
            return _http(404, b'{"message": "Not Found"}')
        if rest == "":
            head = self._git(bare, "symbolic-ref", "--short", "HEAD", env=env).text.strip()
            body = {"default_branch": head, "allow_merge_commit": self.merge_commit_allowed.get(slug, True)}
            return _http(200, json.dumps(body).encode())
        if rest.startswith("contents/"):
            file_path, _, query = rest[len("contents/"):].partition("?ref=")
            shown = self._git(bare, "show", f"{query}:{file_path}", env=env)
            if shown.rc != 0:
                return _http(404, b'{"message": "Not Found"}')
            return _http(200, shown.stdout)
        if rest.startswith("compare/"):
            base, _, head = rest[len("compare/"):].partition("...")
            counts = self._git(bare, "rev-list", "--left-right", "--count", f"{base}...{head}", env=env)
            if counts.rc != 0:
                return _http(404, b'{"message": "Not Found"}')
            behind, ahead = (int(x) for x in counts.text.split())
            status = ("identical" if not (ahead or behind) else "ahead" if not behind
                      else "behind" if not ahead else "diverged")
            return _http(200, json.dumps({"status": status, "ahead_by": ahead, "behind_by": behind}).encode())
        m = re.fullmatch(r"actions/runs/(\d+)/jobs(?:\?.*)?", rest)
        if m:
            jobs = [j for j in self.jobs.values() if j.get("run_id") == int(m.group(1))]
            return _http(200, json.dumps({"total_count": len(jobs), "jobs": jobs}).encode())
        m = re.fullmatch(r"actions/jobs/(\d+)", rest)
        if m:
            job = self.jobs.get(int(m.group(1)))
            return _http(200, json.dumps(job).encode()) if job is not None else _http(404, b"{}")
        m = re.fullmatch(r"check-runs/(\d+)/annotations(?:\?.*)?", rest)
        if m:
            return _http(200, json.dumps(self.annotations.get(int(m.group(1)), [])).encode())
        if rest.startswith("actions/workflows/"):
            state = self.workflows.get((slug, rest[len("actions/workflows/"):]))
            if state is None:
                return _http(404, b"{}")
            return _http(200, json.dumps({"state": state}).encode())
        raise AssertionError(f"unrouted gh api path: {path!r}")

    # -- pull requests -------------------------------------------------------

    def _project(self, pr: dict, fields: str) -> dict:
        return {f: pr.get(f) for f in fields.split(",")}

    def _find(self, slug: str, number: int) -> dict | None:
        return next((p for p in self.prs.get(slug, []) if p["number"] == number), None)

    def _pr_list(self, argv: tuple[str, ...], slug: str, env: Mapping[str, str]) -> Result:
        head, base = _flag(argv, "--head"), _flag(argv, "--base")
        state = (_flag(argv, "--state") or "open").upper()
        found = [p for p in self.prs.get(slug, []) if state == "ALL" or p.get("state", "OPEN") == state
                 and (head is None or p.get("headRefName") == head)
                 and (base is None or p.get("baseRefName", "main") == base)]
        out = [self._project(p, _flag(argv, "--json") or "number") for p in found]
        return Result(argv, 0, json.dumps(out).encode(), b"", False)

    def _pr_view(self, argv: tuple[str, ...], slug: str, env: Mapping[str, str]) -> Result:
        pr = self._find(slug, int(argv[3]))
        if pr is None:
            return Result(argv, 1, b"", b"GraphQL: Could not resolve to a PullRequest", False)
        pr.setdefault("state", "OPEN")
        return Result(argv, 0, json.dumps(self._project(pr, _flag(argv, "--json") or "number")).encode(), b"", False)

    def _pr_create(self, argv: tuple[str, ...], slug: str, env: Mapping[str, str]) -> Result:
        head, base = _flag(argv, "--head"), _flag(argv, "--base")
        bare = self.bares.get(slug)
        oid = None
        if bare is not None:
            got = self._git(bare, "rev-parse", f"refs/heads/{head}", env=env)
            oid = got.text.strip() if got.rc == 0 else None
        number = max((p["number"] for p in self.prs.get(slug, [])), default=0) + 1
        url = f"https://github.com/{slug}/pull/{number}"
        self.prs.setdefault(slug, []).append({
            "number": number, "url": url, "state": "OPEN", "headRefName": head, "baseRefName": base,
            "headRefOid": oid, "isCrossRepository": False, "author": {"login": self.login},
            "title": _flag(argv, "--title"), "mergeCommit": None, "mergeable": "MERGEABLE",
            "mergeStateStatus": "CLEAN", "statusCheckRollup": []})
        return Result(argv, 0, (url + "\n").encode(), b"", False)

    def _pr_close(self, argv: tuple[str, ...], slug: str, env: Mapping[str, str]) -> Result:
        number = int(argv[3])
        pr = self._find(slug, number)
        if pr is None:
            return Result(argv, 1, b"", b"GraphQL: Could not resolve to a PullRequest", False)
        pr["state"] = "CLOSED"
        self.closed_comments[(slug, number)] = _flag(argv, "--comment") or ""
        return Result(argv, 0, b"", b"", False)

    def _pr_merge(self, argv: tuple[str, ...], slug: str, env: Mapping[str, str]) -> Result:
        pr = self._find(slug, int(argv[3]))
        expect = _flag(argv, "--match-head-commit")
        if pr is None:
            return Result(argv, 1, b"", b"GraphQL: Could not resolve to a PullRequest", False)
        if pr.get("state", "OPEN") != "OPEN":
            return Result(argv, 1, b"", b"Pull request is not open", False)
        if pr["headRefOid"] != expect:
            return Result(argv, 1, b"", b"Head branch was modified. Review and try the merge again.", False)
        bare = self.bares[slug]
        base = pr.get("baseRefName", "main")
        clean = {k: v for k, v in env.items() if not k.startswith("GIT_")}
        with tempfile.TemporaryDirectory(dir=clean.get("HOME")) as tmp:
            work = Path(tmp) / "w"

            def git(*a: str) -> str:
                r = proc.run(("git", "-c", "user.name=Fleet Test", "-c", "user.email=test@example.com", *a),
                             cwd=Path(tmp) if a[0] == "clone" else work, env=clean, timeout=60)
                assert r.rc == 0, f"fake merge: git {a} failed: {r.stderr!r}"
                return r.text.strip()

            git("clone", "-q", "--no-local", "--branch", base, str(bare), str(work))
            git("merge", "--no-ff", "-m", f"Merge pull request #{pr['number']}", pr["headRefOid"])
            merge = git("rev-parse", "HEAD")
            git("push", "-q", "origin", f"HEAD:refs/heads/{base}")
        pr["state"] = "MERGED"
        pr["mergeCommit"] = {"oid": merge}
        return Result(argv, 0, b"", b"", False)

    # -- actions -------------------------------------------------------------

    def _run_list(self, argv: tuple[str, ...], slug: str, env: Mapping[str, str]) -> Result:
        wanted = {"headSha": _flag(argv, "--commit"), "headBranch": _flag(argv, "--branch"),
                  "event": _flag(argv, "--event")}
        workflow = _flag(argv, "--workflow")
        found = [r for r in self.runs.get(slug, [])
                 if all(v is None or r.get(k) == v for k, v in wanted.items())
                 and (workflow is None or workflow in (r.get("workflowName"), r.get("workflowFile")))]
        fields = _flag(argv, "--json") or "databaseId"
        return Result(argv, 0, json.dumps([{f: r.get(f) for f in fields.split(",")} for r in found]).encode(),
                      b"", False)
