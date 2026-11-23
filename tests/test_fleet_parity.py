"""The fleet's stdlib-only ports must agree with agent-ratchet's own code at this commit (lock grammar, profile
parsing and predicates, fingerprints of the predicate and loader, allowed keys and limits)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_ratchet import git_guard_io, json_safety, lock_policy
from agent_ratchet.ast_safety import GuardAnalysisError
from agent_ratchet.php.scope import php_profile_active
from fleet_import import guard_fleet, load_tree_from_worktree
from lock_grammar_cases import LOCK_GRAMMAR_CASES

guard_fleet()

from guard_fleet import lockfile, profile  # noqa: E402
from guard_fleet.classify import fingerprints  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
CONFIG_REL = "scripts/audit/audit_guard_config.json"


def _nested(depth: int) -> str:
    return "[" * depth + "]" * depth


def _cfg(**keys: object) -> bytes:
    return json.dumps(keys).encode("utf-8")


# (id, config bytes or None for "no file"). Configs are top-level keys, as the loader reads them.
PROFILE_TABLE: list[tuple[str, bytes | None]] = [
    ("none", None),
    ("empty-object", b"{}"),
    ("php", _cfg(languages=["php"])),
    ("magento-with-php", _cfg(languages=["php"], frameworks=["magento"])),
    ("magento-without-php", _cfg(frameworks=["magento"])),
    ("empty-lists", _cfg(languages=[], frameworks=[])),
    ("unknown-language", _cfg(languages=["python"])),
    ("unknown-framework", _cfg(languages=["php"], frameworks=["laravel"])),
    ("languages-not-a-list", _cfg(languages="php")),
    ("languages-non-string", _cfg(languages=[1])),
    ("languages-duplicate-value", _cfg(languages=["php", "php"])),
    ("frameworks-null", _cfg(languages=["php"], frameworks=None)),
    ("unknown-key", _cfg(profile={"languages": ["php"]})),
    ("other-allowed-keys-only", _cfg(import_roots=["src"], php_paths=["src/"])),
    ("duplicate-key-last-wins", b'{"languages": ["php"], "languages": []}'),
    ("duplicate-key-bad-last", b'{"languages": [], "languages": "php"}'),
    ("nan", b'{"languages": NaN}'),
    ("top-level-array", b"[]"),
    ("top-level-null", b"null"),
    ("empty-bytes", b""),
    ("truncated", b'{"languages": ["php"'),
    ("invalid-utf8", b'{"languages": ["ph\xff"]}'),
    ("utf8-bom", b"\xef\xbb\xbf" + _cfg(languages=["php"])),
    ("oversize-valid", b'{"languages": ["php"], "import_roots": ["src"], "x": "' + b"a" * 2_000_000 + b'"}'),
    ("oversize-valid-allowed", _cfg(languages=["php"], import_roots=["a" * 1_000_000])),
    ("nesting-at-limit",
     b'{"extra_slop_rules": [{"pattern": "x", "k": ' + _nested(json_safety.MAX_JSON_DEPTH - 3).encode() + b"}]}"),
    ("nesting-over-limit",
     b'{"extra_slop_rules": [{"pattern": "x", "k": ' + _nested(json_safety.MAX_JSON_DEPTH + 40).encode() + b"}]}"),
    ("nesting-bracket-in-string",
     b'{"extra_slop_rules": [{"pattern": "x", "k": "' + b"[" * 500 + b'"}]}'),
    ("deep-profile-list", b'{"languages": ' + _nested(300).encode() + b"}"),
]


def _real_loader(raw: bytes | None, tmp_path: Path) -> tuple[bool, bool] | str:
    """agent-ratchet's `_read_guard_config_for_ref` on a worktree holding `raw`, then its two predicates.

    `load_guard_config_for_ref` is not used: its `require_profile_capabilities` step needs the optional PHP extras,
    which the no-extras job lacks, and it is not part of what the fleet ports.
    """
    if raw is not None:
        target = tmp_path / CONFIG_REL
        target.parent.mkdir(parents=True)
        target.write_bytes(raw)
    try:
        cfg = git_guard_io._read_guard_config_for_ref("WORKTREE", str(tmp_path))
    except GuardAnalysisError:
        return "rejected"
    return php_profile_active(cfg), "magento" in cfg.get("frameworks", ())


@pytest.mark.parametrize("raw,expected", LOCK_GRAMMAR_CASES)
def test_lock_grammar_parity(raw, expected):
    # Both regexes are bytes patterns used with `.match` (the core's own parser does `_LOCK_RE.match(raw)`).
    core = lock_policy._LOCK_RE.match(raw)
    ours = lockfile.LOCK_RE.match(raw)
    assert bool(ours) == bool(core) == (expected is not None)
    assert bool(lockfile.LOCK_RE.fullmatch(raw)) == bool(lock_policy._LOCK_RE.fullmatch(raw))
    if expected is None:
        with pytest.raises(lockfile.LockParseError):
            lockfile.parse_lock(raw)
    else:
        spec = lockfile.parse_lock(raw)
        assert (spec.sha, spec.extras) == (expected.sha, expected.extras)


def test_lock_regex_source_is_identical():
    assert lockfile.LOCK_RE.pattern == lock_policy._LOCK_RE.pattern
    assert lockfile.LOCK_RE.flags == lock_policy._LOCK_RE.flags


@pytest.mark.parametrize("raw", [row[1] for row in PROFILE_TABLE], ids=[row[0] for row in PROFILE_TABLE])
def test_profile_predicates_parity(raw, tmp_path):
    ours = profile.parse_profile(raw)
    theirs = _real_loader(raw, tmp_path)
    if theirs == "rejected":
        assert ours.status == "unparseable", ours
    else:
        assert ours.status in ("ok", "missing"), ours
        assert (profile.php_active(ours), profile.magento_active(ours)) == theirs


def test_profile_table_covers_both_outcomes():
    outcomes = {profile.parse_profile(raw).status for _, raw in PROFILE_TABLE}
    assert outcomes == {"missing", "ok", "unparseable"}
    assert len(PROFILE_TABLE) >= 12


def test_missing_config_profile_matches_default_guard_config():
    cfg = git_guard_io.default_guard_config()
    ours = profile.parse_profile(None)
    assert ours.status == "missing"
    assert (profile.php_active(ours), profile.magento_active(ours)) == (
        php_profile_active(cfg), "magento" in cfg.get("frameworks", ()))
    assert ("src/agent_ratchet/git_guard_io.py", "default_guard_config") in fingerprints.FINGERPRINT_TARGETS


def test_fingerprints_match_code_at_this_commit():
    tree = load_tree_from_worktree(ROOT)
    assert fingerprints.mismatches(tree) == ()


def test_allowed_config_keys_and_limits_match():
    assert profile.ALLOWED_CONFIG_KEYS == git_guard_io.ALLOWED_CONFIG_KEYS
    assert profile._PROFILE_VALUES == git_guard_io.PROFILE_VALUES
    assert profile.MAX_JSON_DEPTH == json_safety.MAX_JSON_DEPTH == 128
    assert profile._TOKEN_RE.pattern == json_safety._TOKEN_RE.pattern
    assert profile._TOKEN_RE.flags == json_safety._TOKEN_RE.flags
