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


def tree_from(files: Mapping[str, str], scripts: Mapping[str, str] | None = None,
              pyproject: bytes | None = None) -> SourceTree:
    """A tree of regular files; the cli stub is added unless `files` brings its own cli.py."""
    texts = {CLI_PATH: CLI_STUB, **files}
    return SourceTree(
        commit=FIXTURE_COMMIT,
        files={path: text.encode("utf-8") for path, text in texts.items()},
        modes={path: "100644" for path in texts},
        scripts=dict(DEFAULT_SCRIPTS if scripts is None else scripts),
        pyproject=pyproject,
    )


# The §6.13 refinement layout: transition_scan reaches each scan module only inside its G-block; php/scan.py's
# dedupe helper lives in a core module; magento/scan.py imports magento.di in two ungated helpers and after its
# G-early (as magento/scan.py does at v4.3.4), and magento/di.py imports magento.xml_safe at top level.
REFINED_TRANSITION_SCAN = '''"""Transition scan: language adapters behind profile gates."""

from __future__ import annotations

from agent_ratchet.php.scope import php_profile_active
from agent_ratchet.violation_dedupe import dedupe_php_violations


def transition_violations(cfg, entries):
    found = []
    if php_profile_active(cfg):
        from agent_ratchet.php.scan import php_transition_violations
        found.extend(php_transition_violations(cfg, entries))
    if "magento" in cfg.get("frameworks", ()):
        from agent_ratchet.magento.scan import magento_transition_violations
        found.extend(magento_transition_violations(cfg, entries))
    return dedupe_php_violations(found)
'''

REFINED_LAYOUT = {
    "src/agent_ratchet/cli.py": (
        "from agent_ratchet.transition_scan import transition_violations\n\n\n"
        "def main() -> int:\n    return len(transition_violations({}, []))\n"
    ),
    "src/agent_ratchet/transition_scan.py": REFINED_TRANSITION_SCAN,
    "src/agent_ratchet/violation_dedupe.py": "def dedupe_php_violations(found):\n    return sorted(set(found))\n",
    "src/agent_ratchet/php/scope.py": SCOPE,
    "src/agent_ratchet/php/scan.py": (
        "from agent_ratchet.violation_dedupe import dedupe_php_violations\n\n\n"
        "def php_transition_violations(cfg, entries):\n    return dedupe_php_violations(entries)\n"
    ),
    "src/agent_ratchet/magento/scan.py": '''from agent_ratchet.php.scope import is_in_scope


def _di_pairs(entries):
    from agent_ratchet.magento.di import di_location
    return [di_location(e) for e in entries]


def _shadow_counts(analysis):
    from agent_ratchet.magento.di import PLUGIN, PREFERENCE
    return analysis.count(PLUGIN), analysis.count(PREFERENCE)


def magento_transition_violations(cfg, entries):
    if "magento" not in cfg.get("frameworks", ()):
        return []
    from agent_ratchet.magento.compare import compare_di
    from agent_ratchet.magento.di import analyze_di
    return compare_di([analyze_di(p) for p in _di_pairs(entries)])
''',
    "src/agent_ratchet/magento/di.py": (
        "from agent_ratchet.magento.xml_safe import parse_xml\n\n"
        "PLUGIN = \"plugin\"\nPREFERENCE = \"preference\"\n\n\n"
        "def di_location(path):\n    return path\n\n\n"
        "def analyze_di(path):\n    return parse_xml(path)\n"
    ),
    "src/agent_ratchet/magento/xml_safe.py": "def parse_xml(raw):\n    return raw\n",
    "src/agent_ratchet/magento/compare.py": "def compare_di(sides):\n    return list(sides)\n",
}

REFINED_TRANSITION_GATES = frozenset({("agent_ratchet.transition_scan", 11), ("agent_ratchet.transition_scan", 14)})
