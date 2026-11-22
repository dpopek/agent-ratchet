"""The git wrapper: safe flags, error classification and small query helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Callable, Mapping

from .proc import Result, Runner

GIT_SAFE = ("-c", "maintenance.auto=false", "-c", "gc.auto=0")

_NETWORK_MARKERS = (b"Could not resolve host", b"Failed to connect", b"Connection timed out",
                    b"Operation timed out", b"unable to access", b"Connection reset")


class GitError(Exception):
    def __init__(self, result: Result) -> None:
        tail = result.stderr.decode("utf-8", errors="replace").strip()
        super().__init__(f"git failed (rc={result.rc}): {' '.join(result.argv[1 + len(GIT_SAFE):])}: {tail}")
        self.result = result


class GitLockError(GitError):
    pass


class GitNetworkError(GitError):
    pass


def _is_lock_error(stderr: bytes) -> bool:
    if b".lock': File exists" in stderr:
        return True
    start = stderr.find(b"Unable to create '")
    return start != -1 and b".lock'" in stderr[start:]


class Git:
    def __init__(self, run: Runner, env: Mapping[str, str], sleep: Callable[[float], None], *,
                 timeout: float = 120, backoff: tuple[float, ...] = (1, 2, 4)) -> None:
        self.run = run
        self.env = dict(env)
        self.sleep = sleep
        self.timeout = timeout
        self.backoff = backoff

    def __call__(self, repo: Path, *args: str, check: bool = True, timeout: float | None = None,
                 env: Mapping[str, str] | None = None, input: bytes | None = None,
                 log: Path | None = None) -> Result:
        result = self.run(("git", *GIT_SAFE, *args), cwd=repo,
                          env={**self.env, **(env or {}), "LC_ALL": "C"},  # stderr markers are English
                          timeout=self.timeout if timeout is None else timeout, input=input, log=log)
        if check and result.rc != 0:
            if _is_lock_error(result.stderr):
                raise GitLockError(result)
            if any(m in result.stderr for m in _NETWORK_MARKERS):
                raise GitNetworkError(result)
            raise GitError(result)
        return result

    def retrying(self, repo: Path, *args: str) -> Result:
        """Run a network command, retrying network errors over the backoff schedule."""
        for delay in self.backoff:
            try:
                return self(repo, *args)
            except GitNetworkError:
                self.sleep(delay)
        return self(repo, *args)


def rev_parse(git: Git, repo: Path, rev: str) -> str | None:
    r = git(repo, "rev-parse", "--verify", "--quiet", rev, check=False)
    return r.text.strip() if r.rc == 0 and r.text.strip() else None


def is_ancestor(git: Git, repo: Path, a: str, b: str) -> bool:
    r = git(repo, "merge-base", "--is-ancestor", a, b, check=False)
    if r.rc == 0:
        return True
    if r.rc == 1:
        return False
    raise GitError(r)


def object_type(git: Git, repo: Path, obj: str) -> str | None:
    r = git(repo, "cat-file", "-t", obj, check=False)
    return r.text.strip() if r.rc == 0 else None


def show_bytes(git: Git, repo: Path, rev: str, path: str) -> bytes | None:
    r = git(repo, "cat-file", "blob", f"{rev}:{path}", check=False)
    return r.stdout if r.rc == 0 else None


def ls_remote(git: Git, cwd: Path, url: str, ref: str) -> dict[str, str]:
    out = git.retrying(cwd, "ls-remote", url, ref).text
    refs: dict[str, str] = {}
    for line in out.splitlines():
        sha, _, name = line.partition("\t")
        if name:
            refs[name] = sha
    return refs


def fetch_default(git: Git, repo: Path, branch: str) -> None:
    git.retrying(repo, "fetch", "--no-tags", "--no-write-fetch-head", "--refmap=",
                 "origin", f"refs/heads/{branch}")


def has_commit(git: Git, repo: Path, sha: str) -> bool:
    return git(repo, "cat-file", "-e", f"{sha}^{{commit}}", check=False).rc == 0


def diff_name_status(git: Git, repo: Path, a: str, b: str) -> list[tuple[str, str]]:
    parts = git(repo, "diff", "--name-status", "-z", "--no-renames", a, b).stdout.decode(
        "utf-8", errors="surrogateescape").split("\0")
    if parts and parts[-1] == "":
        parts.pop()
    return [(parts[i], parts[i + 1]) for i in range(0, len(parts) - 1, 2)]


def status_porcelain(git: Git, repo: Path, *, ignored: bool = False) -> list[str]:
    args = ["status", "--porcelain", "-z", "--untracked-files=all"]
    if ignored:
        args.append("--ignored=matching")
    parts = git(repo, *args).stdout.decode("utf-8", errors="surrogateescape").split("\0")
    entries: list[str] = []
    i = 0
    while i < len(parts):
        entry = parts[i]
        i += 1
        if not entry:
            continue
        if entry[0] in "RC" or entry[1:2] in ("R", "C"):
            i += 1  # the rename/copy source follows as its own field
        entries.append(entry)
    return entries


def origin_url(git: Git, repo: Path) -> str | None:
    r = git(repo, "config", "--get", "remote.origin.url", check=False)
    return r.text.strip() if r.rc == 0 and r.text.strip() else None
