"""The dedupe helper lives in core, and core imports no PHP/Magento scan module unless a profile gate opens."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from agent_ratchet.git_guard_io import SlopViolation
from agent_ratchet.violation_dedupe import DEDUPED_PREFIXES, PHP_CATEGORY_PREFIX, dedupe_php_violations

ROOT = Path(__file__).resolve().parents[1]


def run_isolated(mod: str) -> str:
    return subprocess.run(
        [sys.executable, "-I", "-c", f"import {mod}, sys, json; print(json.dumps(sorted(sys.modules)))"],
        check=True, capture_output=True, text=True, cwd=ROOT,
    ).stdout


def test_dedupe_drops_repeated_php_and_magento_findings_only():
    php = SlopViolation("a.php", 3, "php_suppression_rebound", "m", "s")
    mag = SlopViolation("etc/di.xml", 1, "magento_di_plugin_disabled", "m", "s")
    other = SlopViolation("a.py", 1, "syntax_error", "m", "s")
    assert dedupe_php_violations([php, php, mag, mag, other, other]) == [php, mag, other, other]


def test_dedupe_prefixes():
    assert DEDUPED_PREFIXES == ("php_", "magento_") and PHP_CATEGORY_PREFIX == "php_"


def test_helper_has_one_home():
    import agent_ratchet.php.scan as php_scan
    assert not hasattr(php_scan, "dedupe_php_violations") and not hasattr(php_scan, "DEDUPED_PREFIXES")


@pytest.mark.parametrize("mod", ["agent_ratchet.transition_scan", "agent_ratchet.ai_slop_scanner", "agent_ratchet.cli"])
def test_core_import_loads_no_scan_module(mod):
    loaded = set(json.loads(run_isolated(mod)))
    assert not loaded & {"agent_ratchet.php.scan", "agent_ratchet.magento.scan",
                         "agent_ratchet.magento.di", "agent_ratchet.magento.xml_safe"}
