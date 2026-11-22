"""The gh CLI wrapper: every call names its repository; transient failures retry with backoff."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from .exits import FleetExit
from .proc import Result, Runner

_SHA_RE = re.compile(r"[0-9a-f]{40}")
_STATUS_RE = re.compile(rb"HTTP/\S+\s+(\d{3})")
_NETWORK_MARKERS = (b"error connecting", b"Could not resolve host", b"connection refused",
                    b"connection reset", b"i/o timeout", b"no such host", b"TLS handshake",
                    b"timeout", b"EOF", b"HTTP 429", b"rate limit")
_HTTP_IN_STDERR = re.compile(rb"HTTP (\d{3})")
_PR_FIELDS = "number,url,headRefOid,isCrossRepository,author,headRefName"
_RUN_FIELDS = "databaseId,status,conclusion,workflowName,headSha,event,createdAt"


class GhError(Exception):
    exit_code: int | None = None

    def __init__(self, status: int | None, message: str) -> None:
        super().__init__(f"gh failed ({status if status is not None else 'no status'}): {message}")
        self.status = status
        self.message = message


class GhAuthError(GhError):
    exit_code = int(FleetExit.CANCELLED)  # exit 4, the code the fleet reserves for auth/network stops


class GhNetworkError(GhError):
    exit_code = int(FleetExit.CANCELLED)


class GhNotFound(GhError):
    pass


@dataclass(frozen=True)
class GhResponse:
    status: int
    headers: dict[str, str]
    body: bytes

    def json(self) -> Any:
        return json.loads(self.body.decode("utf-8"))


class _Transient(Exception):
    def __init__(self, status: int | None, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


def _parse_response(out: bytes) -> tuple[GhResponse, bool] | None:
    """Parse `gh api -i` output: status line, headers, blank line, body.

    The flag says whether the header/body separator was found (False: the stream was cut short).
    """
    m = _STATUS_RE.match(out)
    if m is None:
        return None
    sep = re.search(rb"\r?\n\r?\n", out)
    head, body = (out[:sep.start()], out[sep.end():]) if sep else (out, b"")
    headers: dict[str, str] = {}
    for line in head.splitlines()[1:]:
        name, colon, value = line.partition(b":")
        if colon:
            headers[name.decode("latin-1").strip().lower()] = value.decode("latin-1").strip()
    return GhResponse(int(m.group(1)), headers, body), sep is not None


def _tail(r: Result) -> str:
    return r.stderr.decode("utf-8", errors="replace").strip() or r.stdout.decode("utf-8", errors="replace").strip()


class Gh:
    def __init__(self, run: Runner, env: Mapping[str, str], sleep: Callable[[float], None], cwd: Path, *,
                 timeout: float = 60, backoff: tuple[float, ...] = (1, 2, 4, 8, 16)) -> None:
        self.run = run
        self.env = dict(env)
        self.sleep = sleep
        self.cwd = cwd
        self.timeout = timeout
        self.backoff = backoff

    # -- transport ---------------------------------------------------------

    def _retrying(self, attempt: Callable[[], Any], *, single: bool = False) -> Any:
        # single: a mutating call runs once; a transient failure raises so the caller can reconcile
        for delay in (None,) if single else (*self.backoff, None):
            try:
                return attempt()
            except _Transient as exc:
                if delay is None:
                    raise GhNetworkError(exc.status, exc.message) from None
                self.sleep(delay)
        raise AssertionError("unreachable")

    def _exec(self, argv: Sequence[str]) -> Result:
        return self.run(tuple(argv), cwd=self.cwd, env=self.env, timeout=self.timeout)

    def api(self, path: str, *, method: str = "GET", accept: str | None = None) -> GhResponse:
        argv = ["gh", "api", "-i"]
        if method != "GET":
            argv += ["-X", method]
        if accept is not None:
            argv += ["-H", f"Accept: {accept}"]
        argv.append(path)

        def attempt() -> GhResponse:
            r = self._exec(argv)
            if r.rc == 127:
                raise GhError(None, _tail(r))
            if r.timed_out:
                raise _Transient(None, "timed out")
            parsed = _parse_response(r.stdout)
            if parsed is None:
                if r.rc == 4:
                    raise GhAuthError(None, _tail(r))
                if r.rc != 0:
                    raise _Transient(None, _tail(r))
                raise GhError(None, "unparseable gh api output")
            resp, complete = parsed
            if resp.status == 401:
                raise GhAuthError(401, _tail(r) or resp.body.decode("utf-8", errors="replace"))
            if resp.status == 404:
                raise GhNotFound(404, resp.body.decode("utf-8", errors="replace"))
            if (resp.status == 429 or resp.status >= 500
                    or (resp.status == 403 and resp.headers.get("x-ratelimit-remaining") == "0")):
                raise _Transient(resp.status, resp.body.decode("utf-8", errors="replace"))
            if resp.status >= 400:
                raise GhError(resp.status, resp.body.decode("utf-8", errors="replace"))
            if r.rc != 0:
                raise _Transient(resp.status, f"gh exited {r.rc} after a {resp.status} status: {_tail(r)}")
            if not complete:
                raise GhError(resp.status, "gh api output has no header/body separator")
            return resp

        return self._retrying(attempt, single=method != "GET")

    def _gh(self, *args: str, mutating: bool = False) -> Result:
        """Run a non-api gh command; classify failures by exit code and stderr."""
        argv = ("gh", *args)

        def attempt() -> Result:
            r = self._exec(argv)
            if r.rc == 0:
                return r
            if r.rc == 127:
                raise GhError(None, _tail(r))
            if r.timed_out:
                raise _Transient(None, "timed out")
            m = _HTTP_IN_STDERR.search(r.stderr)
            status = int(m.group(1)) if m else None
            if r.rc == 4 or status == 401:
                raise GhAuthError(status, _tail(r))
            if status == 404 or b"Could not resolve to" in r.stderr:
                raise GhNotFound(status, _tail(r))
            if (status is not None and (status == 429 or status >= 500)) or any(
                    mk in r.stderr for mk in _NETWORK_MARKERS):
                raise _Transient(status, _tail(r))
            raise GhError(status, _tail(r))

        return self._retrying(attempt, single=mutating)

    def _json(self, *args: str) -> Any:
        return json.loads(self._gh(*args).stdout.decode("utf-8"))

    # -- repository ----------------------------------------------------------

    def contents_raw(self, slug: str, path: str, ref: str) -> bytes | None:
        try:
            return self.api(f"repos/{slug}/contents/{path}?ref={ref}",
                            accept="application/vnd.github.raw+json").body
        except GhNotFound:
            return None

    def repo_visible(self, slug: str) -> None:
        self.api(f"repos/{slug}")

    def default_branch(self, slug: str) -> str:
        return str(self.api(f"repos/{slug}").json()["default_branch"])

    def merge_commit_allowed(self, slug: str) -> bool:
        return bool(self.api(f"repos/{slug}").json()["allow_merge_commit"])

    def user_login(self) -> str:
        return str(self.api("user").json()["login"])

    def compare(self, slug: str, base: str, head: str) -> dict:
        return self.api(f"repos/{slug}/compare/{base}...{head}").json()

    def workflow_state(self, slug: str, workflow: str) -> str:
        return str(self.api(f"repos/{slug}/actions/workflows/{workflow}").json()["state"])

    # -- pull requests -------------------------------------------------------

    def pr_list(self, slug: str, *, head: str, base: str) -> list[dict]:
        return self._json("pr", "list", "--repo", slug, "--head", head, "--base", base,
                          "--state", "open", "--json", _PR_FIELDS)

    def pr_list_open(self, slug: str, *, base: str) -> list[dict]:
        return self._json("pr", "list", "--repo", slug, "--base", base, "--state", "open",
                          "--limit", "100", "--json", _PR_FIELDS)

    def pr_view(self, slug: str, number: int, fields: Sequence[str]) -> dict:
        return self._json("pr", "view", str(number), "--repo", slug, "--json", ",".join(fields))

    def pr_create(self, slug: str, *, head: str, base: str, title: str, body_file: Path) -> str:
        r = self._gh("pr", "create", "--repo", slug, "--head", head, "--base", base,
                     "--title", title, "--body-file", str(body_file), mutating=True)
        return r.text.strip().splitlines()[-1]

    def pr_close(self, slug: str, number: int, comment: str) -> None:
        self._gh("pr", "close", str(number), "--repo", slug, "--comment", comment, mutating=True)

    def pr_merge(self, slug: str, number: int, head_sha: str) -> Result:
        if not _SHA_RE.fullmatch(head_sha):
            raise ValueError(f"head_sha must be 40 lower-case hex characters: {head_sha!r}")
        # one attempt, no retry: a retried merge could land twice; callers re-read with pr_view
        return self._exec(("gh", "pr", "merge", str(number), "--repo", slug, "--merge",
                           "--match-head-commit", head_sha))

    # -- actions -------------------------------------------------------------

    def run_list(self, slug: str, *, commit: str | None = None, workflow: str | None = None,
                 branch: str | None = None, event: str | None = None) -> list[dict]:
        args = ["run", "list", "--repo", slug]
        for flag, value in (("--commit", commit), ("--workflow", workflow),
                            ("--branch", branch), ("--event", event)):
            if value is not None:
                args += [flag, value]
        return self._json(*args, "--limit", "100", "--json", _RUN_FIELDS)

    def job(self, slug: str, job_id: int) -> dict:
        return self.api(f"repos/{slug}/actions/jobs/{job_id}").json()

    def check_run_annotations(self, slug: str, check_run_id: int) -> list[dict]:
        return self.api(f"repos/{slug}/check-runs/{check_run_id}/annotations?per_page=100").json()
