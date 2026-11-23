from __future__ import annotations

import hashlib
import re
from collections.abc import Iterator
from pathlib import Path

from test_php_golden import _FORBIDDEN_DIGESTS, _FORBIDDEN_LENGTHS, _has_forbidden_word

ROOT = Path(__file__).resolve().parents[1]
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

# SHA-256 of private lower-case words that must never appear under fleet/; only the digests are written here.
FLEET_DIGESTS = frozenset(
    {
        "4512192ed41c2e00d17a241fea6b79a7a7ea6ca4bb85cfedbdbd766d49fec2b8",
        "bc1bb13064b20a3f9113b447237c494238fb71284c02a7036a6799a587eeac32",
        "cc372569871eff45984bd785fd432e822baa81b1fedc16796468095370b63da3",
        "672b4b36f77663a4e67b40e45168bd720574923edb683fa495543b1c33206745",
        "5d98352b326a8ac23699046249acfcdf21b540d7055015ec549fc8ab2a62fba8",
        "9efe96b96cf1953ea7d746ff0146ba4f0bda8fa15640cc1cfef58d7cb825ecd3",
        "0042dd33bc50eb79a867235f379cbd533cdecd1b5e7eb0d64c9c725b7ce3e4f8",
    }
)
FLEET_LENGTHS = (7, 9, 12, 13, 14, 16)
ALL_DIGESTS = _FORBIDDEN_DIGESTS | FLEET_DIGESTS
ALL_LENGTHS = tuple(sorted(set(_FORBIDDEN_LENGTHS) | set(FLEET_LENGTHS)))


def _sha(word: str) -> str:
    return hashlib.sha256(word.encode("utf-8")).hexdigest()


def fleet_texts() -> Iterator[tuple[Path, str]]:
    for path in sorted((ROOT / "fleet").rglob("*")):
        if not path.is_file() or "__pycache__" in path.parts:
            continue
        try:
            yield path, path.read_bytes().decode("utf-8")
        except UnicodeDecodeError:
            continue


def test_fleet_tree_has_no_private_names() -> None:
    seen = 0
    for path, text in fleet_texts():
        seen += 1
        assert not _has_forbidden_word(text.lower(), ALL_DIGESTS, ALL_LENGTHS), path
    assert seen > 0


def test_fleet_tree_has_no_user_paths_or_foreign_emails() -> None:
    for path, text in fleet_texts():
        assert "/users/" not in text.lower(), path
        assert all(m.endswith("@example.com") for m in EMAIL_RE.findall(text)), path


def test_detector_finds_planted_word() -> None:
    assert _has_forbidden_word("xx canaryword yy", frozenset({_sha("canaryword")}), (10,))
    assert not _has_forbidden_word("xx neutralword yy", frozenset({_sha("canaryword")}), (10,))


def test_fleet_license_equals_root_license() -> None:
    assert (ROOT / "fleet/LICENSE").read_bytes() == (ROOT / "LICENSE").read_bytes()
