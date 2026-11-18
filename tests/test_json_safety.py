"""Bounded JSON loader: depth limit, string handling, malformed input, speed."""

from __future__ import annotations

import json
import time

import pytest

from agent_ratchet.json_safety import MAX_JSON_DEPTH, JsonTooDeepError, loads_bounded


def nest(n):
    return "[" * n + "]" * n


def test_depth_at_limit_parses():
    assert loads_bounded(nest(MAX_JSON_DEPTH)) is not None


def test_depth_over_limit_raises_with_position():
    with pytest.raises(JsonTooDeepError) as e:
        loads_bounded(nest(MAX_JSON_DEPTH + 1))
    assert str(e.value).startswith("nesting deeper than 128") and e.value.pos == MAX_JSON_DEPTH
    assert isinstance(e.value, json.JSONDecodeError)


@pytest.mark.parametrize("text", ['{"a": "' + "[" * 600 + '"}', '{"a": "x\\"' + "{" * 600 + '"}'])
def test_brackets_inside_strings_ignored(text):
    assert isinstance(loads_bounded(text), dict)


@pytest.mark.parametrize("text", ['{"a": "unterminated', '[]]', '{"a": [}'])
def test_malformed_still_json_decode_error(text):
    with pytest.raises(json.JSONDecodeError):
        loads_bounded(text)


def test_deep_100k_raises_without_recursion():
    with pytest.raises(JsonTooDeepError):
        loads_bounded(nest(100_000))


def test_large_flat_input_is_fast():
    text = json.dumps({"exemptions": [{"path": f"src/f{i}.py", "n": i} for i in range(30_000)]})
    assert len(text) > 1_000_000
    t = time.perf_counter()
    loads_bounded(text)
    assert time.perf_counter() - t < 0.5


def test_unterminated_string_scan_is_linear():
    text = '"' + '\\"' * 50_000
    t = time.perf_counter()
    with pytest.raises(json.JSONDecodeError) as e:
        loads_bounded(text)
    elapsed = time.perf_counter() - t
    assert not isinstance(e.value, JsonTooDeepError)
    assert elapsed < 0.5


def test_unterminated_string_then_brackets_is_plain_decode_error():
    with pytest.raises(json.JSONDecodeError) as e:
        loads_bounded('"abc' + "[" * 600)
    assert not isinstance(e.value, JsonTooDeepError)
