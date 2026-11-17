"""Black-box: self-skip names exempt files only under their own prefix (scripts/audit/, tests/).

Drives `python -m agent_ratchet` in subprocesses only and imports nothing from agent_ratchet, so the same file
can run against another engine via AGENT_RATCHET_ENGINE_SRC.
"""

from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from guard_repo_harness import _commit_files, _git, _init_guard_repo, _run_baseline_guard, _run_scanner, _write_files

APP_FILE = "src/source_metrics.py"
GUARD_FILE = "scripts/audit/source_metrics.py"
CLEAN = "def total(a: int, b: int) -> int:\n    return a + b\n"
WIDE_SIGNATURE = CLEAN + "def wide(a, b, c, d, e, f):\n    return a\n"
CHATTY = "# Certainly! Here is the implementation:\n" + CLEAN
OVERSIZED = "".join(f"value_{i} = {i}\n" for i in range(1000))


class SelfSkipScopeTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.repo = _init_guard_repo(self._tmp.name)
        self.base = _commit_files(self.repo, "chore: initial", {"src/app.py": CLEAN}, include_guards=True)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _assert_reported(self, result, path: str, category: str) -> None:
        out = result.stderr + result.stdout
        self.assertEqual(result.returncode, 1, out)
        self.assertIn(f"{path}:", out)
        self.assertIn(f"[{category}]", out)

    def test_staged_scan_reports_violation_in_app_file_named_like_guard_module(self) -> None:
        _write_files(self.repo, {APP_FILE: WIDE_SIGNATURE})
        _git(self.repo, "add", APP_FILE)
        self._assert_reported(_run_scanner(self.repo, "--staged-only"), APP_FILE, "excessive_parameter_list")

    def test_diff_base_reports_violation_in_app_file_named_like_guard_module(self) -> None:
        head = _commit_files(self.repo, "feat: metrics", {APP_FILE: WIDE_SIGNATURE})
        result = _run_scanner(self.repo, "--diff-base", self.base, "--head-ref", head)
        self._assert_reported(result, APP_FILE, "excessive_parameter_list")

    def test_commit_range_reports_violation_in_app_file_named_like_guard_module(self) -> None:
        head = _commit_files(self.repo, "feat: metrics", {APP_FILE: WIDE_SIGNATURE})
        self._assert_reported(_run_scanner(self.repo, "--commit-range", f"{self.base}..{head}"), APP_FILE, "excessive_parameter_list")

    def test_staged_file_size_budget_applies_to_app_file_named_like_guard_module(self) -> None:
        _write_files(self.repo, {APP_FILE: OVERSIZED})
        _git(self.repo, "add", APP_FILE)
        self._assert_reported(_run_scanner(self.repo, "--staged-only"), APP_FILE, "modified_file_loc_buffer")

    def test_import_cycle_through_app_file_named_like_guard_module_is_reported(self) -> None:
        _write_files(self.repo, {
            "src/pkg/__init__.py": "",
            "src/pkg/source_metrics.py": "from . import peer\n",
            "src/pkg/peer.py": "from . import source_metrics\n",
        })
        _git(self.repo, "add", "src/pkg")
        self._assert_reported(_run_scanner(self.repo, "--staged-only"), "src/pkg/source_metrics.py", "import_cycle")

    def test_guard_module_under_scripts_audit_keeps_its_skip(self) -> None:
        _write_files(self.repo, {GUARD_FILE: WIDE_SIGNATURE})
        _git(self.repo, "add", GUARD_FILE)
        result = _run_scanner(self.repo, "--staged-only")
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)

    def test_file_scan_decides_identically_for_all_path_spellings(self) -> None:
        _write_files(self.repo, {APP_FILE: CHATTY, GUARD_FILE: CHATTY})
        root = self.repo.resolve()
        for spelling in (GUARD_FILE, f"./{GUARD_FILE}", str(root / GUARD_FILE)):
            with self.subTest(guard=spelling):
                result = _run_scanner(self.repo, spelling)
                self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        for spelling in (APP_FILE, f"./{APP_FILE}", str(root / APP_FILE)):
            with self.subTest(app=spelling):
                result = _run_scanner(self.repo, spelling)
                self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
                self.assertIn("source_metrics.py:1", result.stderr)

    def test_rename_out_of_scripts_audit_makes_new_path_scanned(self) -> None:
        _commit_files(self.repo, "chore: vendored module", {GUARD_FILE: CLEAN})
        _git(self.repo, "mv", GUARD_FILE, APP_FILE)
        _write_files(self.repo, {APP_FILE: WIDE_SIGNATURE})
        _git(self.repo, "add", APP_FILE)
        self._assert_reported(_run_scanner(self.repo, "--staged-only"), APP_FILE, "excessive_parameter_list")

    def test_rename_into_scripts_audit_mixed_with_code_fails_policy_isolation(self) -> None:
        _commit_files(self.repo, "feat: metrics", {APP_FILE: CLEAN})
        _git(self.repo, "mv", APP_FILE, GUARD_FILE)
        _write_files(self.repo, {"src/app.py": CLEAN + "EXTRA = 1\n"})
        _git(self.repo, "add", "src/app.py")
        result = _run_baseline_guard(self.repo, "--enforce-policy-isolation")
        self.assertNotEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn("Policy isolation violation", result.stderr + result.stdout)


if __name__ == "__main__":
    unittest.main()
