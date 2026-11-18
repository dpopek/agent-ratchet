"""Bounded JSON parsing: fail closed on excessive nesting on every Python version.

``json.loads`` raises RecursionError on deep nesting only on some interpreters
(3.15 parses 100k levels). Guard config and baselines are untrusted input, so
nesting is bounded explicitly and reported as a ``json.JSONDecodeError``
subclass, which callers already treat as a malformed-input (fail-closed) error.
"""

from __future__ import annotations

import json
import re
from typing import Any

MAX_JSON_DEPTH: int = 128

# Strings are matched whole so brackets inside them are ignored. The closing quote is
# optional so an unterminated string is consumed to EOF in one pass (linear time);
# json.loads then reports it.
_TOKEN_RE = re.compile(r'"(?:[^"\\]|\\.)*"?|[\[\]{}]', re.S)


class JsonTooDeepError(json.JSONDecodeError):
    """Raised when JSON nesting exceeds MAX_JSON_DEPTH."""


def loads_bounded(text: str) -> Any:
    """Parse JSON text, raising JsonTooDeepError when nesting exceeds MAX_JSON_DEPTH."""
    depth = 0
    for m in _TOKEN_RE.finditer(text):
        c = m.group()
        if c in "[{":
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise JsonTooDeepError(f"nesting deeper than {MAX_JSON_DEPTH}", text, m.start())
        elif c in "]}":
            depth -= 1
    return json.loads(text)
