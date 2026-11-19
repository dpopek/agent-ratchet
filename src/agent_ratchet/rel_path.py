"""Shared repository-relative path syntax check for config entries."""

from __future__ import annotations

GLOB_CHARS = "*?["


def clean_rel_segments(path: str) -> bool:
    """True when `path` is slash-separated with no backslash, glob character, or empty/'.'/'..' segment."""
    if "\\" in path or any(c in path for c in GLOB_CHARS):
        return False
    return all(seg not in ("", ".", "..") for seg in path.split("/"))
