import json

import pytest

from guard_fleet.profile import (ALLOWED_CONFIG_KEYS, MAX_JSON_DEPTH, Profile, loads_bounded, magento_active,
                                 parse_profile, php_active)


@pytest.mark.parametrize("raw,php,magento", [
    (None, False, False),
    (b'{"languages": ["php"]}', True, False),
    (b'{"languages": ["php"], "frameworks": ["magento"]}', True, True),
    (b'{"languages": ["python"]}', False, False),   # not a known value: the guard rejects it
    (b'{}', False, False),
    (b'{"import_roots": ["src"]}', False, False)])
def test_profile_predicates(raw, php, magento):
    p = parse_profile(raw)
    assert (php_active(p), magento_active(p)) == (php, magento)


def test_status_per_input():
    assert parse_profile(None).status == "missing"
    assert parse_profile(b'{"languages": ["php"]}') == Profile("ok", frozenset({"php"}), frozenset(), "")
    assert parse_profile(b'{"frameworks": []}').status == "ok"


@pytest.mark.parametrize("raw", [
    b"{not json",
    b"[]",
    b"null",
    b"\xff\xfe",                                              # not UTF-8
    b'{"profile": {"languages": ["php"]}}',                   # unknown key: there is no wrapper key
    b'{"languages": "php"}',
    b'{"languages": ["php", "php"]}',
    b'{"languages": [1]}',
    b'{"frameworks": ["magento"]}',                           # magento without php
    b'{"languages": [], "frameworks": ["magento"]}',
    b'{"frameworks": ["laravel"]}'])
def test_rejected_configs_are_unparseable(raw):
    p = parse_profile(raw)
    assert p.status == "unparseable" and p.reason
    assert (php_active(p), magento_active(p)) == (False, False)


def test_depth_bound_matches_the_core_value():
    assert MAX_JSON_DEPTH == 128


def _nested(depth: int) -> str:
    return "[" * depth + "]" * depth


def test_depth_at_the_bound_parses_and_beyond_is_rejected():
    assert loads_bounded(_nested(MAX_JSON_DEPTH)) is not None
    with pytest.raises(json.JSONDecodeError):
        loads_bounded(_nested(MAX_JSON_DEPTH + 1))
    deep = ('{"extra_slop_rules": ' + _nested(MAX_JSON_DEPTH + 1) + "}").encode()
    assert parse_profile(deep).status == "unparseable"


def test_brackets_inside_strings_do_not_count():
    assert loads_bounded(json.dumps({"k": "[" * 500})) == {"k": "[" * 500}


def test_allowed_keys_cover_the_profile_keys():
    assert {"languages", "frameworks"} <= ALLOWED_CONFIG_KEYS
