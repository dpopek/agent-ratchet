"""JS/TS quality-config protection in policy isolation."""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

import pytest

from agent_ratchet.git_guard_io import is_protected_governance_path
from agent_ratchet.test_baseline_integrity import _check_single_commit_policy_isolation

sys.path.insert(0, str(Path(__file__).resolve().parent))
from guard_repo_harness import _commit_files, _init_guard_repo  # noqa: E402

JS_NAMES = [
    "eslint.config.js", "eslint.config.mts", ".eslintrc", ".eslintrc.cjs", ".eslintrc.yaml", ".eslintignore",
    "tsconfig.json", "tsconfig.app.json", "packages/ui/tsconfig.build.json", "jsconfig.json", "jsconfig.app.json",
    "knip.json", "knip.ts", ".knip.jsonc",
    "vitest.config.ts", "vitest.workspace.ts", "vite.config.ts", "jest.config.cjs",
    "playwright.config.ts", "playwright.frontend-only.config.ts",
    ".prettierrc", ".prettierrc.json", "prettier.config.mjs", ".prettierignore",
    "biome.json", "biome.jsonc", ".lintstagedrc", "lint-staged.config.js",
    ".stylelintrc.json", "stylelint.config.cjs", ".dependency-cruiser.cjs", "apps/web/eslint.config.mjs",
]


@pytest.mark.parametrize("prefix", ["", "apps/web/"])
@pytest.mark.parametrize("name", JS_NAMES)
def test_js_quality_configs_protected(name: str, prefix: str) -> None:
    assert is_protected_governance_path(prefix + name) is True


@pytest.mark.parametrize("path", [
    "src/eslint.config.test.ts", "src/tsconfig-helpers.ts", "src/tsconfig.ts", "docs/eslint.md",
    "src/vite-env.d.ts", "eslint.config.js.bak", "node_modules/foo/tsconfig.json",
    "packages/a/node_modules/eslint.config.js",
])
def test_js_lookalikes_not_protected(path: str) -> None:
    assert is_protected_governance_path(path) is False


def _isolation(files: dict[str, str]) -> tuple[bool, str]:
    with tempfile.TemporaryDirectory() as tmp:
        repo = _init_guard_repo(tmp)
        base = _commit_files(repo, "base", {"README.md": "x\n"})
        head = _commit_files(repo, "change", files)
        return _check_single_commit_policy_isolation(base, head, cwd=str(repo))


def test_eslint_config_with_src_fails() -> None:
    ok, msg = _isolation({"eslint.config.js": "export default [];\n", "src/a.ts": "export {};\n"})
    assert ok is False
    assert "eslint.config.js" in msg


def test_eslint_config_alone_passes() -> None:
    ok, _ = _isolation({"eslint.config.js": "export default [];\n"})
    assert ok is True


def test_nested_tsconfig_with_src_fails() -> None:
    ok, _ = _isolation({"packages/ui/tsconfig.json": "{}\n", "packages/ui/src/a.ts": "export {};\n"})
    assert ok is False
