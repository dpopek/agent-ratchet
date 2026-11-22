"""In-memory source trees for classifier tests (no git)."""

from __future__ import annotations

from typing import Mapping

from guard_fleet.classify.tree import SourceTree

FIXTURE_COMMIT = "1" * 40
DEFAULT_SCRIPTS = {"agent-ratchet": "agent_ratchet.cli:main"}
CLI_PATH = "src/agent_ratchet/cli.py"
CLI_STUB = "def main() -> int:\n    return 0\n"

SCOPE = '''"""Which paths and profiles the PHP adapter covers."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def php_profile_active(cfg: Mapping[str, Any]) -> bool:
    return "php" in cfg.get("languages", ()) or "magento" in cfg.get("frameworks", ())
'''


def tree_from(files: Mapping[str, str], scripts: Mapping[str, str] | None = None) -> SourceTree:
    """A tree of regular files; the cli stub is added unless `files` brings its own cli.py."""
    texts = {CLI_PATH: CLI_STUB, **files}
    return SourceTree(
        commit=FIXTURE_COMMIT,
        files={path: text.encode("utf-8") for path, text in texts.items()},
        modes={path: "100644" for path in texts},
        scripts=dict(DEFAULT_SCRIPTS if scripts is None else scripts),
    )
