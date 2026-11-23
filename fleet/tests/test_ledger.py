"""Run ledger: append-only, fsynced, and a fail-closed gated-attempt lookup."""

from __future__ import annotations

import json
import os
import stat

import pytest
from fakes import FakeClock
from guard_fleet.ledger import GATES, Ledger, Record, gated_attempt, prune_tag_dirs

HEAD = "h" * 40
BASE = "b" * 40


@pytest.fixture
def ledger(tmp_path):
    return Ledger(tmp_path / "state" / "v4.4.0" / "ledger.jsonl", FakeClock())


def gate_record(attempt, consumer, gate, verdict="PASS", reason=""):
    return Record(
        ts="2026-11-22T00:00:00Z",
        attempt=attempt,
        consumer=consumer,
        step=gate,
        argv=None,
        rc=None,
        base=None,
        head=None,
        log=None,
        detail={"verdict": verdict, "reason": reason},
    )


def full_attempt(ledger, consumer, *, head=HEAD, ok=True, verdicts=None, skip=()):
    a = ledger.start_attempt(consumer, BASE)
    for gate in GATES:
        if gate in skip:
            continue
        ledger.record(gate_record(a, consumer, gate, (verdicts or {}).get(gate, "PASS")))
    ledger.end_attempt(a, consumer, head=head, ok=ok)
    return a


def lookup(ledger, consumer="alpha", head=HEAD):
    return gated_attempt(*ledger.records(), consumer, head)


def test_gated_attempt_needs_complete_passing_attempt(ledger):
    a = full_attempt(ledger, "alpha", head=HEAD)
    assert lookup(ledger) == (a, "")


def test_na_counts_as_pass(ledger):
    a = full_attempt(ledger, "alpha", verdicts={"G3": "n/a", "G7": "n/a"})
    assert lookup(ledger) == (a, "")


def test_partial_or_later_failed_attempt_is_not_gated(ledger):
    full_attempt(ledger, "alpha", head=HEAD)
    ledger.start_attempt("alpha", BASE)  # later partial attempt
    assert lookup(ledger)[0] is None


def test_later_failed_attempt_is_not_gated(ledger):
    full_attempt(ledger, "alpha", head=HEAD)
    full_attempt(ledger, "alpha", head=HEAD, ok=False)
    got, reason = lookup(ledger)
    assert got is None and reason


def test_other_consumer_later_attempt_does_not_interfere(ledger):
    a = full_attempt(ledger, "alpha", head=HEAD)
    ledger.start_attempt("beta", BASE)
    assert lookup(ledger) == (a, "")
    assert lookup(ledger, "beta")[0] is None


def test_unparsable_line_means_not_gated(ledger):
    full_attempt(ledger, "alpha", head=HEAD)
    with ledger.path.open("a") as fh:
        fh.write("{broken\n")
    records, bad = ledger.records()
    assert bad == [len(records) + 1]
    assert gated_attempt(records, bad, "alpha", HEAD)[0] is None


@pytest.mark.parametrize(
    "line",
    [
        "[]",
        "{}",
        '{"ts": 1}',
        "",
        (
            '{"ts":"t","attempt":"a","consumer":"alpha","step":"G1","argv":"x","rc":null,'
            '"base":null,"head":null,"log":null,"detail":{}}'
        ),
        (
            '{"ts":"t","attempt":"a","consumer":"alpha","step":"G1","argv":null,"rc":true,'
            '"base":null,"head":null,"log":null,"detail":{}}'
        ),
    ],
)
def test_malformed_lines_are_reported_by_number(ledger, line):
    ledger.start_attempt("alpha", BASE)
    with ledger.path.open("a") as fh:
        fh.write(line + "\n")
    records, bad = ledger.records()
    assert len(records) == 1 and bad == [2]


def test_unterminated_tail_is_a_bad_line(ledger):
    full_attempt(ledger, "alpha")
    with ledger.path.open("a") as fh:
        fh.write(json.dumps({"ts": "t"}))  # torn write, no newline
    assert lookup(ledger)[0] is None


def test_non_utf8_line_is_bad_not_a_crash(ledger):
    ledger.start_attempt("alpha", BASE)
    with ledger.path.open("ab") as fh:
        fh.write(b"\xff\xfe\n")
    _, bad = ledger.records()
    assert bad == [2]


def test_missing_gate_record_is_not_a_pass(ledger):
    full_attempt(ledger, "alpha", skip=("G5",))
    got, reason = lookup(ledger)
    assert got is None and "G5" in reason


@pytest.mark.parametrize("verdict", ["FAIL", "pass", "", "skip"])
def test_non_passing_gate_verdict_is_not_gated(ledger, verdict):
    full_attempt(ledger, "alpha", verdicts={"G4": verdict})
    got, reason = lookup(ledger)
    assert got is None and "G4" in reason


def test_latest_record_of_a_gate_wins(ledger):
    a = ledger.start_attempt("alpha", BASE)
    for gate in GATES:
        ledger.record(gate_record(a, "alpha", gate))
    ledger.record(gate_record(a, "alpha", "G2", "FAIL"))
    ledger.end_attempt(a, "alpha", head=HEAD, ok=True)
    assert lookup(ledger)[0] is None


def test_head_must_match(ledger):
    full_attempt(ledger, "alpha", head=HEAD)
    got, reason = lookup(ledger, head="c" * 40)
    assert got is None and reason


def test_attempt_without_end_is_partial(ledger):
    a = ledger.start_attempt("alpha", BASE)
    for gate in GATES:
        ledger.record(gate_record(a, "alpha", gate))
    assert lookup(ledger)[0] is None


def test_end_without_start_is_ignored(ledger):
    ledger.end_attempt("alpha-1", "alpha", head=HEAD, ok=True)
    for gate in GATES:
        ledger.record(gate_record("alpha-1", "alpha", gate))
    assert lookup(ledger)[0] is None


def test_earlier_attempt_on_other_head_does_not_match(ledger):
    full_attempt(ledger, "alpha", head="c" * 40)
    b = full_attempt(ledger, "alpha", head=HEAD)
    assert lookup(ledger) == (b, "")
    assert lookup(ledger, head="c" * 40)[0] == "alpha-1"


def test_empty_or_missing_ledger_is_not_gated(ledger):
    assert ledger.records() == ([], [])
    assert lookup(ledger)[0] is None


def test_attempt_ids_count_earlier_starts_per_consumer(ledger):
    assert ledger.start_attempt("alpha", BASE) == "alpha-1"
    assert ledger.start_attempt("beta", BASE) == "beta-1"
    assert ledger.start_attempt("alpha", BASE) == "alpha-2"


def test_start_record_carries_base_and_end_carries_head(ledger):
    a = ledger.start_attempt("alpha", BASE)
    ledger.end_attempt(a, "alpha", head=HEAD, ok=False)
    start, end = ledger.records()[0]
    assert (start.step, start.base, start.attempt) == ("attempt-start", BASE, a)
    assert (end.step, end.head, end.detail["ok"]) == ("attempt-end", HEAD, False)


def test_record_round_trips(ledger):
    rec = Record(
        ts="2026-11-22T10:00:00Z",
        attempt="alpha-1",
        consumer="alpha",
        step="c2",
        argv=("git", "commit"),
        rc=0,
        base=BASE,
        head=HEAD,
        log="/x/y.log",
        detail={"k": [1, "v"]},
    )
    ledger.record(rec)
    assert ledger.records() == ([rec], [])


def test_heads_recorded(ledger):
    full_attempt(ledger, "alpha", head=HEAD)
    full_attempt(ledger, "beta", head="c" * 40)
    ledger.start_attempt("alpha", BASE)
    assert ledger.heads_recorded("alpha") == {HEAD}
    assert ledger.heads_recorded("gamma") == set()


def test_records_are_fsynced(ledger, monkeypatch):
    calls = []
    monkeypatch.setattr(os, "fsync", lambda fd: calls.append(fd))
    ledger.start_attempt("alpha", BASE)
    assert calls


def test_one_json_line_per_record_and_append_only(ledger):
    full_attempt(ledger, "alpha")
    first = ledger.path.read_bytes()
    full_attempt(ledger, "beta")
    second = ledger.path.read_bytes()
    assert second.startswith(first)
    assert second.endswith(b"\n")
    assert all(json.loads(line) for line in second.splitlines())


def test_file_is_created_private(ledger):
    ledger.start_attempt("alpha", BASE)
    assert stat.S_IMODE(ledger.path.stat().st_mode) == 0o600


def test_file_is_private_even_under_a_permissive_umask(ledger):
    old = os.umask(0)
    try:
        ledger.start_attempt("alpha", BASE)
    finally:
        os.umask(old)
    assert stat.S_IMODE(ledger.path.stat().st_mode) == 0o600


def test_timestamp_comes_from_the_clock(ledger):
    ledger.start_attempt("alpha", BASE)
    assert ledger.records()[0][0].ts == "2023-11-14T22:13:20Z"


def test_prune_keeps_last_five_tags(tmp_path):
    tmp_path = tmp_path / "state"
    tmp_path.mkdir()
    for v in ["v4.3.0", "v4.3.1", "v4.3.2", "v4.3.3", "v4.3.4", "v4.4.0", "v4.10.0", "notes"]:
        (tmp_path / v).mkdir()
    removed = prune_tag_dirs(tmp_path)
    assert sorted(p.name for p in tmp_path.iterdir()) == [
        "notes",
        "v4.10.0",
        "v4.3.2",
        "v4.3.3",
        "v4.3.4",
        "v4.4.0",
    ]
    assert sorted(p.name for p in removed) == ["v4.3.0", "v4.3.1"]


def test_prune_leaves_files_and_lookalikes_alone(tmp_path):
    tmp_path = tmp_path / "state"
    tmp_path.mkdir()
    for v in ["v4.1.0", "v4.1.1", "v5.0.0", "v4.01.0", "v4.2.0-rc1"]:
        (tmp_path / v).mkdir()
    (tmp_path / "v4.0.9").write_text("a file")
    assert prune_tag_dirs(tmp_path, keep=1) == [tmp_path / "v4.1.0"]
    assert (tmp_path / "v4.0.9").exists() and (tmp_path / "v5.0.0").exists()
    assert (tmp_path / "v4.01.0").exists() and (tmp_path / "v4.2.0-rc1").exists()


def test_prune_missing_state_dir_is_a_noop(tmp_path):
    assert prune_tag_dirs(tmp_path / "absent") == []


@pytest.mark.parametrize("verdict", [["PASS"], {"v": "PASS"}, 1, None])
def test_non_string_gate_verdict_is_not_gated_without_raising(ledger, verdict):
    full_attempt(ledger, "alpha", verdicts={"G6": verdict})
    got, reason = lookup(ledger)
    assert got is None and "G6" in reason
