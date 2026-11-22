"""A consumer's guard profile (``scripts/audit/audit_guard_config.json``) read the way the guard reads it.

The rules below mirror agent-ratchet at v4.3.4: ``json_safety.loads_bounded`` (``MAX_JSON_DEPTH``, the token scan),
``git_guard_io.ALLOWED_CONFIG_KEYS`` / ``PROFILE_VALUES`` / ``_parse_profile`` and the profile checks at the end of
``parse_guard_config_bytes``, and ``php.scope.php_profile_active``. The fleet never imports agent_ratchet; the parity
test in the root suite is the judge of the copy.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Literal

MAX_JSON_DEPTH: int = 128

# json_safety._TOKEN_RE: strings are matched whole so brackets inside them are ignored.
_TOKEN_RE = re.compile(r'"(?:[^"\\]|\\.)*"?|[\[\]{}]', re.S)

# git_guard_io.ALLOWED_CONFIG_KEYS
ALLOWED_CONFIG_KEYS = frozenset({"extra_slop_rules", "legacy_loc_waivers", "import_roots", "self_skip", "languages",
                                 "frameworks", "php_paths", "php_suppression_exceptions", "magento_di_exceptions"})
# git_guard_io.PROFILE_VALUES
_PROFILE_VALUES = {"languages": frozenset({"php"}), "frameworks": frozenset({"magento"})}


class JsonTooDeepError(json.JSONDecodeError):
    """Nesting deeper than MAX_JSON_DEPTH."""


def loads_bounded(text: str) -> Any:
    """json_safety.loads_bounded: parse JSON text, failing closed on nesting deeper than MAX_JSON_DEPTH."""
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


@dataclass(frozen=True)
class Profile:
    status: Literal["missing", "ok", "unparseable"]
    languages: frozenset[str]
    frameworks: frozenset[str]
    reason: str


def _unparseable(reason: str) -> Profile:
    return Profile("unparseable", frozenset(), frozenset(), reason)


def _values(data: dict[str, Any], key: str) -> frozenset[str] | None:
    """`_parse_profile`: a list of unique strings, each from the key's known values; None when invalid."""
    values, known = data.get(key, []), _PROFILE_VALUES[key]
    if not isinstance(values, list) or any(not isinstance(v, str) or v not in known for v in values):
        return None
    if len(set(values)) != len(values):
        return None
    return frozenset(values)


def parse_profile(raw: bytes | None) -> Profile:
    """The profile in the config bytes; any config the guard would reject is `unparseable` (the fleet then
    treats the consumer as exposed to every surface)."""
    if raw is None:
        return Profile("missing", frozenset(), frozenset(), "no audit_guard_config.json")
    try:
        data = loads_bounded(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        return _unparseable(f"malformed audit_guard_config.json: {exc}")
    if not isinstance(data, dict):
        return _unparseable("audit_guard_config.json must be a JSON object")
    if unknown := sorted(set(data) - ALLOWED_CONFIG_KEYS):
        return _unparseable(f"unknown key(s) in audit_guard_config.json: {unknown}")
    languages, frameworks = _values(data, "languages"), _values(data, "frameworks")
    if languages is None or frameworks is None:
        return _unparseable("invalid languages or frameworks in audit_guard_config.json")
    if "magento" in frameworks and "php" not in languages:
        return _unparseable("frameworks 'magento' requires languages 'php'")
    return Profile("ok", languages, frameworks, "")


def php_active(p: Profile) -> bool:
    """`php_profile_active` on the loader's parsed config."""
    return "php" in p.languages or "magento" in p.frameworks


def magento_active(p: Profile) -> bool:
    """`"magento" in cfg.get("frameworks", ())` on the loader's parsed config."""
    return "magento" in p.frameworks
