"""Append-only, fsynced run ledger and the fail-closed gated-attempt lookup."""

from __future__ import annotations

import json
import os
import re
import shutil
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from guard_fleet.deps import Clock

GATES = ("G1", "G2", "G3", "G4", "G5", "G6", "G7", "G8", "G9")
_PASSING = frozenset({"PASS", "n/a"})
_TAG_DIR = re.compile(r"v4\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")


@dataclass(frozen=True)
class Record:
    ts: str
    attempt: str
    consumer: str
    step: str
    argv: tuple[str, ...] | None
    rc: int | None
    base: str | None
    head: str | None
    log: str | None
    detail: Mapping[str, object]

    def to_json(self) -> str:
        return json.dumps(
            {
                "ts": self.ts,
                "attempt": self.attempt,
                "consumer": self.consumer,
                "step": self.step,
                "argv": None if self.argv is None else list(self.argv),
                "rc": self.rc,
                "base": self.base,
                "head": self.head,
                "log": self.log,
                "detail": dict(self.detail),
            },
            sort_keys=True,
            separators=(",", ":"),
        )


def _opt_str(value: object) -> bool:
    return value is None or isinstance(value, str)


def _parse(line: bytes) -> Record | None:
    """One ledger line to a Record, or None when it is not a well-formed record."""
    try:
        obj = json.loads(line.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return None
    if not isinstance(obj, dict):
        return None
    argv, rc, detail = obj.get("argv"), obj.get("rc"), obj.get("detail")
    if not all(isinstance(obj.get(k), str) for k in ("ts", "attempt", "consumer", "step")):
        return None
    if not all(_opt_str(obj.get(k)) for k in ("base", "head", "log")):
        return None
    if argv is not None and not (isinstance(argv, list) and all(isinstance(a, str) for a in argv)):
        return None
    if rc is not None and (isinstance(rc, bool) or not isinstance(rc, int)):
        return None
    if not isinstance(detail, dict):
        return None
    return Record(
        ts=obj["ts"],
        attempt=obj["attempt"],
        consumer=obj["consumer"],
        step=obj["step"],
        argv=None if argv is None else tuple(argv),
        rc=rc,
        base=obj.get("base"),
        head=obj.get("head"),
        log=obj.get("log"),
        detail=detail,
    )


def _utc(epoch: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))


class Ledger:
    def __init__(self, path: Path, clock: Clock) -> None:
        self.path = path
        self.clock = clock

    def _now(self) -> str:
        return _utc(self.clock.wall())

    def start_attempt(self, consumer: str, base: str) -> str:
        records, _ = self.records()
        earlier = sum(1 for r in records if r.consumer == consumer and r.step == "attempt-start")
        attempt = f"{consumer}-{earlier + 1}"
        self.record(
            Record(self._now(), attempt, consumer, "attempt-start", None, None, base, None, None, {})
        )
        return attempt

    def record(self, rec: Record) -> None:
        data = (rec.to_json() + "\n").encode("utf-8")
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        created = not self.path.exists()
        fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            view = memoryview(data)
            while view:
                view = view[os.write(fd, view) :]
            os.fsync(fd)
        finally:
            os.close(fd)
        if created:
            dfd = os.open(self.path.parent, os.O_RDONLY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)

    def end_attempt(self, attempt: str, consumer: str, *, head: str | None, ok: bool) -> None:
        self.record(
            Record(self._now(), attempt, consumer, "attempt-end", None, None, None, head, None, {"ok": ok})
        )

    def records(self) -> tuple[list[Record], list[int]]:
        try:
            raw = self.path.read_bytes()
        except FileNotFoundError:
            return [], []
        lines = raw.split(b"\n")
        if lines[-1] == b"":
            lines.pop()
        records: list[Record] = []
        bad: list[int] = []
        last = len(lines)
        torn = not raw.endswith(b"\n")  # an unterminated final line is a torn write
        for number, line in enumerate(lines, start=1):
            rec = None if (number == last and torn) else _parse(line)
            if rec is None:
                bad.append(number)
            else:
                records.append(rec)
        return records, bad

    def heads_recorded(self, consumer: str) -> set[str]:
        records, _ = self.records()
        return {r.head for r in records if r.consumer == consumer and r.head}


def _check_attempt(records: Sequence[Record], attempt: str, head: str) -> str:
    """Empty string when the attempt is complete, ok, on `head` and passed G1-G9; else why not."""
    mine = [r for r in records if r.attempt == attempt]
    ends = [r for r in mine if r.step == "attempt-end"]
    if not ends:
        return f"attempt {attempt} has no end record"
    if any(e.detail.get("ok") is not True for e in ends):
        return f"attempt {attempt} did not end ok"
    if ends[-1].head != head:
        return f"attempt {attempt} ended on a different head"
    for gate in GATES:
        verdicts = [r.detail.get("verdict") for r in mine if r.step == gate]
        if not verdicts:
            return f"attempt {attempt} has no {gate} record"
        if not (isinstance(verdicts[-1], str) and verdicts[-1] in _PASSING):
            return f"attempt {attempt} {gate} is {verdicts[-1]!r}"
    return ""


def gated_attempt(
    records: Sequence[Record], bad_lines: Sequence[int], consumer: str, head: str
) -> tuple[str | None, str]:
    if bad_lines:
        return None, f"ledger has unparsable lines: {list(bad_lines)}"
    starts = [r.attempt for r in records if r.consumer == consumer and r.step == "attempt-start"]
    if not starts:
        return None, f"no attempt recorded for {consumer}"
    latest = starts[-1]
    ends = [r for r in records if r.attempt == latest and r.step == "attempt-end"]
    if not ends:
        return None, f"latest attempt {latest} is partial"
    if any(e.detail.get("ok") is not True for e in ends):
        return None, f"latest attempt {latest} failed"
    reason = ""
    for attempt in reversed(starts):
        reason = _check_attempt(records, attempt, head)
        if not reason:
            return attempt, ""
    return None, f"no gated attempt for {consumer} on {head}: {reason}"


def prune_tag_dirs(state: Path, keep: int = 5) -> list[Path]:
    if not state.is_dir():
        return []
    found: list[tuple[tuple[int, int], Path]] = []
    for child in state.iterdir():
        m = _TAG_DIR.fullmatch(child.name)
        if m and child.is_dir() and not child.is_symlink():
            found.append(((int(m.group(1)), int(m.group(2))), child))
    found.sort(key=lambda item: item[0])
    removed = [path for _, path in found[: max(len(found) - keep, 0)]]
    for path in removed:
        shutil.rmtree(path)
    return removed
