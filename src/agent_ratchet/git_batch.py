"""Blob reads through one `git cat-file --batch` process per scan, with a bounded LRU cache and one-shot fallbacks.

Anything the batch protocol cannot answer byte-identically (non-blob objects, ambiguous names, "missing", git fatal
errors, specs with newline, CR or NUL) is delegated to the one-shot `git cat-file blob` path, so findings, messages and
exit codes match a scan without a session. A per-object timeout disables the reader and the scan continues one-shot.
"""

from __future__ import annotations

from collections import OrderedDict
from contextlib import contextmanager
from contextvars import ContextVar
import os
import re
import selectors
import subprocess
import time
from typing import Iterator, NamedTuple, NoReturn

from agent_ratchet.ast_safety import GuardAnalysisError

_MISSING_MARKERS: tuple[str, ...] = ("not a valid object name", "does not exist", "exists on disk, but not in")
_HEADER_RE = re.compile(rb"([0-9a-f]{40}|[0-9a-f]{64}) ([a-z]+) ([0-9]+)")
# "missing" covers an absent path (one-shot: None), an unresolvable rev and, on old git, a gitlink (one-shot: "bad file"
# error), so every miss is answered by one-shot and never memoised.
_NO_CONTENT_STATUSES: frozenset[bytes] = frozenset({b"ambiguous", b"missing", b"submodule"})
_GIT_FATAL_EXIT = 128
_EXIT_GRACE_S = 2.0
_READ_CHUNK = 1 << 16
# Characters a batch request line cannot carry verbatim: "\n" splits the request, git strips a trailing "\r".
_BATCH_UNSAFE_CHARS: tuple[str, ...] = ("\n", "\r", "\0")


def batch_unsafe(spec: str) -> bool:
    return any(ch in spec for ch in _BATCH_UNSAFE_CHARS)


class _BatchTimeout(Exception):
    """A per-object read exceeded the timeout; the caller disables the reader and falls back to one-shot."""


def _git_env() -> dict[str, str]:
    return {**os.environ, "LC_ALL": "C"}  # stable stderr


def head_commit_exists(cwd: str | None = None) -> bool:
    return subprocess.run(["git", "rev-parse", "--verify", "HEAD^{commit}"], cwd=cwd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def _git_cat_bytes_oneshot(spec: str, cwd: str | None = None) -> bytes | None:
    res = subprocess.run(["git", "cat-file", "blob", spec], cwd=cwd, capture_output=True, env=_git_env())
    if res.returncode == 0:
        return res.stdout
    err = (res.stderr or b"").decode("utf-8", errors="replace").lower()
    if any(marker in err for marker in _MISSING_MARKERS):
        return None
    raise GuardAnalysisError(f"git cat-file failed for '{spec}': {err.strip()}")


class BatchStats(NamedTuple):
    reads: int
    cache_hits: int
    cached_bytes: int


class GitBatchReader:
    """Lazy `git cat-file --batch` client; the process starts on the first batch read and stops on close()."""

    def __init__(self, cwd: str, *, timeout_s: float = 30.0, cache_budget_bytes: int = 64 * 2**20) -> None:
        self._cwd = cwd
        self._timeout_s = timeout_s
        self._budget = cache_budget_bytes
        self._max_entry = cache_budget_bytes // 8
        self._proc: subprocess.Popen[bytes] | None = None
        self._buf = bytearray()
        self._poisoned: str | None = None
        self._disabled = False
        self._blobs: OrderedDict[str, bytes] = OrderedDict()
        self._spec_oids: dict[str, str] = {}
        self._head: bool | None = None
        self._reads = 0
        self._hits = 0
        self._cached_bytes = 0

    def __enter__(self) -> GitBatchReader:
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()

    def close(self) -> None:
        self._stop(kill=False)

    @property
    def stats(self) -> BatchStats:
        return BatchStats(self._reads, self._hits, self._cached_bytes)

    def head_exists(self) -> bool:
        if self._head is None:
            self._head = head_commit_exists(self._cwd)
        return self._head

    def read_path(self, rev: str, path: str) -> bytes | None:
        return self.read_spec(f"{rev}:{path}" if rev else f":{path}")

    def read_spec(self, spec: str) -> bytes | None:
        self._reads += 1
        if self._poisoned is not None:
            raise self._error(spec, f"reader unusable after an earlier failure: {self._poisoned}")
        if self._disabled or batch_unsafe(spec):
            return _git_cat_bytes_oneshot(spec, self._cwd)
        cached = self._cache_get(spec)
        if cached is not None:
            self._hits += 1
            return cached
        return self._query(spec)

    def _query(self, spec: str) -> bytes | None:
        try:
            header, record = self._exchange(spec)
        except _BatchTimeout:
            self._stop(kill=True)
            self._disabled = True  # 3.3.0 had no timeout: finish the scan one-shot instead of failing it
            return _git_cat_bytes_oneshot(spec, self._cwd)
        except BaseException:
            self._stop(kill=True)  # never leave a half-read record in the stream; restart lazily
            raise
        if header is None:  # git exited with a fatal error: the one-shot path reproduces its message
            return _git_cat_bytes_oneshot(spec, self._cwd)
        if record is not None:
            oid, kind, data = record
            if kind != b"blob":
                return _git_cat_bytes_oneshot(spec, self._cwd)
            self._cache_put(spec, oid, data)
            return data
        name, _, status = header.rpartition(b" ")
        if name != os.fsencode(spec) or status not in _NO_CONTENT_STATUSES:
            self._stop(kill=True)  # unknown framing: restart lazily rather than risk a desynced stream
        return _git_cat_bytes_oneshot(spec, self._cwd)

    def _exchange(self, spec: str) -> tuple[bytes | None, tuple[str, bytes, bytes] | None]:
        """One request/response: (header, (oid, type, content) for an object header, else None)."""
        deadline = time.monotonic() + self._timeout_s
        header = self._request(spec, deadline)
        match = _HEADER_RE.fullmatch(header) if header is not None else None
        if match is None:
            return header, None
        data = self._read_exact(int(match.group(3)) + 1, deadline, spec)
        if data[-1:] != b"\n":
            self._fail(spec, "malformed batch output (missing record terminator)")
        return header, (match.group(1).decode("ascii"), match.group(2), data[:-1])

    def _request(self, spec: str, deadline: float) -> bytes | None:
        proc = self._ensure_started()
        try:
            assert proc.stdin is not None
            proc.stdin.write(os.fsencode(spec) + b"\n")
            proc.stdin.flush()
        except OSError:
            return self._header_eof(spec)
        while (idx := self._buf.find(b"\n")) < 0:
            if not self._fill(deadline, spec):
                return self._header_eof(spec)
        line = bytes(self._buf[:idx])
        del self._buf[: idx + 1]
        return line

    def _header_eof(self, spec: str) -> None:
        proc = self._proc
        assert proc is not None
        try:
            code = proc.wait(timeout=_EXIT_GRACE_S)
        except subprocess.TimeoutExpired:
            code = None
        if code == _GIT_FATAL_EXIT:
            self._stop(kill=True)
            return None
        self._fail(spec, f"unexpected end of output (exit code {code})")

    def _read_exact(self, size: int, deadline: float, spec: str) -> bytes:
        while len(self._buf) < size:
            if not self._fill(deadline, spec):
                self._fail(spec, f"short read: expected {size} bytes, got {len(self._buf)}")
        data = bytes(self._buf[:size])
        del self._buf[:size]
        return data

    def _fill(self, deadline: float, spec: str) -> bool:
        proc = self._proc
        assert proc is not None and proc.stdout is not None
        fd = proc.stdout.fileno()
        remaining = deadline - time.monotonic()
        with selectors.DefaultSelector() as sel:
            sel.register(fd, selectors.EVENT_READ)
            ready = remaining > 0 and sel.select(remaining)
        if not ready:
            raise _BatchTimeout(spec)
        chunk = os.read(fd, _READ_CHUNK)
        self._buf.extend(chunk)
        return bool(chunk)

    def _ensure_started(self) -> subprocess.Popen[bytes]:
        if self._proc is None:
            self._proc = subprocess.Popen(
                ["git", "cat-file", "--batch"], cwd=self._cwd, env=_git_env(),
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0,
            )
        return self._proc

    def _stop(self, *, kill: bool) -> None:
        proc, self._proc = self._proc, None
        self._buf.clear()
        if proc is None:
            return
        if kill:
            proc.kill()
        for stream in (proc.stdin, proc.stdout):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass
        try:
            proc.wait(timeout=_EXIT_GRACE_S)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

    def _error(self, spec: str, reason: str) -> GuardAnalysisError:
        return GuardAnalysisError(f"git cat-file --batch failed for '{spec}': {reason}")

    def _fail(self, spec: str, reason: str) -> NoReturn:
        self._stop(kill=True)
        self._poisoned = reason
        raise self._error(spec, reason)

    def _cache_get(self, spec: str) -> bytes | None:
        oid = self._spec_oids.get(spec)
        if oid is None or oid not in self._blobs:
            return None
        self._blobs.move_to_end(oid)
        return self._blobs[oid]

    def _cache_put(self, spec: str, oid: str, data: bytes) -> None:
        self._spec_oids[spec] = oid
        if len(data) > self._max_entry or oid in self._blobs:
            return
        self._blobs[oid] = data
        self._cached_bytes += len(data)
        while self._cached_bytes > self._budget:
            _, evicted = self._blobs.popitem(last=False)
            self._cached_bytes -= len(evicted)


_ACTIVE: ContextVar[tuple[str, GitBatchReader] | None] = ContextVar("agent_ratchet_git_batch_reader", default=None)


def _session_key(cwd: str | None) -> str | None:
    """Realpath of cwd (default: process cwd); None when it cannot be resolved, e.g. a deleted working directory."""
    try:
        return os.path.realpath(cwd or os.getcwd())
    except OSError:
        return None


@contextmanager
def git_batch_session(cwd: str | None = None) -> Iterator[GitBatchReader | None]:
    """Bind one lazy reader to the scan cwd; git_cat_bytes for that cwd reads through it until the block exits.

    Yields None (no reader bound, every read one-shot as in 3.3.0) when the cwd cannot be resolved.
    """
    key = _session_key(cwd)
    if key is None:
        yield None
        return
    with GitBatchReader(key) as reader:
        token = _ACTIVE.set((key, reader))
        try:
            yield reader
        finally:
            _ACTIVE.reset(token)


def active_reader_for(cwd: str | None) -> GitBatchReader | None:
    bound = _ACTIVE.get()
    if bound is None or _session_key(cwd) != bound[0]:  # an unresolvable cwd (None) never matches
        return None
    return bound[1]
