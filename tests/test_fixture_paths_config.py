"""self_skip.fixture_paths: config validation, base-and-target intersection, and repo-level transition behaviour."""

from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest

import pytest

from agent_ratchet.git_guard_io import GuardAnalysisError, fixture_set, parse_guard_config_bytes

sys.path.insert(0, str(Path(__file__).resolve().parent))
from guard_repo_harness import _commit_files, _init_guard_repo, _json_bytes, _run_scanner

OK = b'{"self_skip": {"fixture_paths": ["tests/ci/test_ai_slop_scanner.py"]}}'
CONFIG = "scripts/audit/audit_guard_config.json"
FIXTURE = "tests/ci/test_x.py"
CHATTY = "# Certainly! Here is the implementation:\nVALUE = 1\n"
ADDED_MESSAGE = f"self_skip.fixture_paths entry added: '{FIXTURE}' (widens the self-skip exemption)"


def _config(*fixtures: str) -> bytes:
    payload: dict[str, object] = {"extra_slop_rules": [], "legacy_loc_waivers": []}
    if fixtures:
        payload["self_skip"] = {"fixture_paths": list(fixtures)}
    return _json_bytes(payload)


def test_valid_fixture_paths_parse() -> None:
    assert parse_guard_config_bytes(OK, "x")["fixture_paths"] == ["tests/ci/test_ai_slop_scanner.py"]


def test_missing_self_skip_defaults_to_empty() -> None:
    assert parse_guard_config_bytes(b"{}", "x")["fixture_paths"] == []


@pytest.mark.parametrize("entry", [
    "tests/../src/app.py", "./tests/a.py", "tests/a/", "tests/*.py", "tests/a?.py", "tests/[a].py",
    "src/a.py", "tests//a.py", "tests\\a.py", "/tests/a.py", "", "tests/./a.py",
])
def test_invalid_fixture_path_is_config_error(entry: str) -> None:
    with pytest.raises(GuardAnalysisError):
        parse_guard_config_bytes(json.dumps({"self_skip": {"fixture_paths": [entry]}}).encode(), "x")


@pytest.mark.parametrize("raw", [
    b'{"self_skip": []}',
    b'{"self_skip": {"fixture_paths": "tests/a.py"}}',
    b'{"self_skip": {"fixture_paths": ["tests/a.py", "tests/a.py"]}}',
    b'{"self_skip": {"fixture_paths": [1]}}',
    b'{"self_skip": {"fixture_path": ["tests/a.py"]}}',
])
def test_malformed_self_skip_is_config_error(raw: bytes) -> None:
    with pytest.raises(GuardAnalysisError):
        parse_guard_config_bytes(raw, "x")


def test_fixture_set_is_intersection() -> None:
    base = {"fixture_paths": ["tests/a.py", "tests/b.py"]}
    assert fixture_set(base, {"fixture_paths": ["tests/b.py", "tests/c.py"]}) == {"tests/b.py"}
    assert fixture_set(None, {"fixture_paths": ["tests/c.py"]}) == {"tests/c.py"}


class FixturePathTransitionTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.repo = _init_guard_repo(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _scan(self, base: str, head: str):
        return _run_scanner(self.repo, "--diff-base", base, "--head-ref", head)

    def test_added_fixture_path_is_reported_and_file_still_scanned(self) -> None:
        base = _commit_files(self.repo, "chore: initial", {CONFIG: _config(), "src/app.py": "X = 1\n"}, include_guards=True)
        head = _commit_files(self.repo, "feat: fixture", {CONFIG: _config(FIXTURE), FIXTURE: CHATTY}, include_guards=True)
        result = self._scan(base, head)
        out = result.stderr + result.stdout
        self.assertEqual(result.returncode, 1, out)
        self.assertIn(ADDED_MESSAGE, out)
        self.assertIn(f"{FIXTURE}:", out)

    def test_listed_fixture_is_skipped(self) -> None:
        base = _commit_files(self.repo, "chore: initial", {CONFIG: _config(FIXTURE), "src/app.py": "X = 1\n"}, include_guards=True)
        head = _commit_files(self.repo, "feat: fixture", {FIXTURE: CHATTY})
        result = self._scan(base, head)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)

    def test_unlisted_test_file_is_scanned(self) -> None:
        base = _commit_files(self.repo, "chore: initial", {CONFIG: _config(), "src/app.py": "X = 1\n"}, include_guards=True)
        head = _commit_files(self.repo, "feat: test", {FIXTURE: CHATTY})
        result = self._scan(base, head)
        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        self.assertIn(f"{FIXTURE}:", result.stderr + result.stdout)

    def test_removed_fixture_path_is_allowed(self) -> None:
        base = _commit_files(self.repo, "chore: initial", {CONFIG: _config(FIXTURE), "src/app.py": "X = 1\n"}, include_guards=True)
        head = _commit_files(self.repo, "chore: drop fixture", {CONFIG: _config()}, include_guards=True)
        result = self._scan(base, head)
        self.assertNotIn("self_skip.fixture_paths", result.stderr + result.stdout)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)


if __name__ == "__main__":
    unittest.main()
