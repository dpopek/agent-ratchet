"""Package version and installed-commit detection (PEP 610 direct_url.json)."""

from __future__ import annotations

import importlib.metadata
import json

VERSION: str = "4.0.0"
_DISTRIBUTION_NAME = "agent-ratchet"


def installed_sha() -> str | None:
    """Return the git commit the package was installed from, or None for non-VCS installs."""
    try:
        raw = importlib.metadata.distribution(_DISTRIBUTION_NAME).read_text("direct_url.json")
    except importlib.metadata.PackageNotFoundError:
        return None
    if not raw:
        return None
    try:
        payload = json.loads(raw)
    except ValueError:
        return None
    vcs_info = payload.get("vcs_info") if isinstance(payload, dict) else None
    commit = vcs_info.get("commit_id") if isinstance(vcs_info, dict) else None
    return commit if isinstance(commit, str) and commit else None

