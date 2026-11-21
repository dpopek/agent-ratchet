"""JS/TS quality-config protection in policy isolation."""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

import pytest

from agent_ratchet.git_guard_io import (
    PACKAGE_JSON_GUARDED_KEYS, is_package_json_path, is_protected_governance_path, package_json_guarded_change,
)
from agent_ratchet.test_baseline_integrity import _check_merge_commit_policy_isolation, _check_single_commit_policy_isolation

sys.path.insert(0, str(Path(__file__).resolve().parent))
from guard_repo_harness import _commit_files, _git, _init_guard_repo, _write_files  # noqa: E402

JS_NAMES = [
    "eslint.config.js", "eslint.config.mts", ".eslintrc", ".eslintrc.cjs", ".eslintrc.yaml", ".eslintignore",
    "tsconfig.json", "tsconfig.app.json", "packages/ui/tsconfig.build.json", "jsconfig.json", "jsconfig.app.json",
    "knip.json", "knip.ts", ".knip.jsonc", "knip.config.ts", "knip.config.js",
    "vitest.config.ts", "vitest.workspace.ts", "vite.config.ts", "jest.config.cjs",
    "vite.frontend-only.config.ts", "jest.config.json", "vitest.workspace.json",
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
    "src/vite-env.d.ts", "vite-env.d.ts", "eslint.config.js.bak", "node_modules/foo/tsconfig.json",
    "packages/a/node_modules/eslint.config.js",
])
def test_js_lookalikes_not_protected(path: str) -> None:
    assert is_protected_governance_path(path) is False


def _isolation(files: dict[str, str], base_files: dict[str, str] | None = None) -> tuple[bool, str]:
    with tempfile.TemporaryDirectory() as tmp:
        repo = _init_guard_repo(tmp)
        base = _commit_files(repo, "base", {"README.md": "x\n", **(base_files or {})})
        head = _commit_files(repo, "change", files)
        return _check_single_commit_policy_isolation(base, head, cwd=str(repo))


PKG_BASE = '{"name": "x", "dependencies": {"a": "1"}, "scripts": {"lint": "eslint .", "test": "vitest"}}\n'


@pytest.mark.parametrize("old,new,expected", [
    (b'{"dependencies":{"a":"1"}}', b'{"dependencies":{"a":"2"}}', False),
    (b'{"scripts":{"lint":"eslint ."}}', b'{"scripts":{"lint":"true"}}', True),
    (b'{"name":"x"}', b'{"name":"x","eslintConfig":{}}', True),
    (b'{"scripts":{"a":"1","b":"2"}}', b'{\n  "scripts": {"b": "2", "a": "1"}\n}\n', False),
    (b'{', b'{}', True),
    (b'{}', b'{', True),
    (b'{}', b'[]', True),
    (b'\xff', b'{}', True),
    (None, b'{"scripts":{}}', True),
    (None, b'{"name":"x"}', False),
    (b'{"jest":{}}', None, True),
    (b'{"simple-git-hooks":{"pre-commit":"npx lint-staged"}}', b'{"simple-git-hooks":{}}', True),
    (b'{"husky":{"hooks":{"pre-commit":"lint-staged"}}}', b'{}', True),
    (b'{"pre-commit":["lint"]}', b'{"pre-commit":[]}', True),
    (b'\xef\xbb\xbf{"scripts":{"a":"1"},"dependencies":{"x":"1"}}', b'\xef\xbb\xbf{"scripts":{"a":"1"},"dependencies":{"x":"2"}}', False),
    (b'\xef\xbb\xbf{"scripts":{"a":"1"}}', b'{"scripts":{"a":"1"}}', False),
    (b'\xef\xbb\xbf{"scripts":{"a":"1"}}', b'\xef\xbb\xbf{"scripts":{"a":"2"}}', True),
])
def test_package_json_guarded_change(old: bytes | None, new: bytes | None, expected: bool) -> None:
    assert package_json_guarded_change(old, new) is expected


def test_package_json_guarded_keys_exact() -> None:
    assert PACKAGE_JSON_GUARDED_KEYS == (
        "scripts", "eslintConfig", "prettier", "jest", "lint-staged", "knip", "stylelint",
        "husky", "simple-git-hooks", "pre-commit",
    )


@pytest.mark.parametrize("path,expected", [
    ("package.json", True), ("apps/web/package.json", True), ("node_modules/a/package.json", False),
    ("package.json.bak", False), ("src/mypackage.json", False),
])
def test_is_package_json_path(path: str, expected: bool) -> None:
    assert is_package_json_path(path) is expected


def test_package_json_deps_only_with_src_passes() -> None:
    new_pkg = PKG_BASE.replace('"a": "1"', '"a": "2"')
    ok, _ = _isolation({"package.json": new_pkg, "src/a.ts": "export {};\n"}, {"package.json": PKG_BASE})
    assert ok is True


def test_package_json_scripts_with_src_fails() -> None:
    new_pkg = PKG_BASE.replace('"eslint ."', '"true"')
    ok, msg = _isolation({"package.json": new_pkg, "src/a.ts": "export {};\n"}, {"package.json": PKG_BASE})
    assert ok is False
    assert msg.startswith("Policy isolation violation")
    assert "package.json" in msg


def test_malformed_package_json_with_src_fails() -> None:
    ok, msg = _isolation({"package.json": "{\n", "src/a.ts": "export {};\n"}, {"package.json": PKG_BASE})
    assert ok is False
    assert "package.json" in msg


def test_package_json_reformat_only_passes() -> None:
    new_pkg = '{\n  "scripts": {\n    "test": "vitest",\n    "lint": "eslint ."\n  },\n  "dependencies": {"a": "1"},\n  "name": "x"\n}\n'
    ok, _ = _isolation({"package.json": new_pkg, "src/a.ts": "export {};\n"}, {"package.json": PKG_BASE})
    assert ok is True


def test_node_modules_package_json_scripts_with_src_passes() -> None:
    nm = "node_modules/foo/package.json"
    ok, _ = _isolation({nm: PKG_BASE.replace('"eslint ."', '"true"'), "src/a.ts": "export {};\n"}, {nm: PKG_BASE})
    assert ok is True


def test_rename_of_protected_config_with_code_fails() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        repo = _init_guard_repo(tmp)
        base = _commit_files(repo, "base", {"README.md": "x\n", "eslint.config.js": "export default [];\n"})
        _git(repo, "mv", "eslint.config.js", "eslint.config.js.off")
        head = _commit_files(repo, "change", {"src/a.ts": "export {};\n"})
        ok, msg = _check_single_commit_policy_isolation(base, head, cwd=str(repo))
    assert ok is False
    assert "eslint.config.js" in msg


@pytest.mark.parametrize("target", [None, "WORKTREE"])
def test_package_json_scripts_with_src_fails_for_index_and_worktree(target: str | None) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        repo = _init_guard_repo(tmp)
        base = _commit_files(repo, "base", {"README.md": "x\n", "package.json": PKG_BASE})
        _write_files(repo, {"package.json": PKG_BASE.replace('"eslint ."', '"true"'), "src/a.ts": "export {};\n"})
        _git(repo, "add", "package.json", "src/a.ts")
        ok, msg = _check_single_commit_policy_isolation(base, target, cwd=str(repo))
    assert ok is False
    assert "package.json" in msg


def test_package_json_deps_only_with_src_passes_for_worktree() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        repo = _init_guard_repo(tmp)
        base = _commit_files(repo, "base", {"README.md": "x\n", "package.json": PKG_BASE})
        _write_files(repo, {"package.json": PKG_BASE.replace('"a": "1"', '"a": "2"'), "src/a.ts": "export {};\n"})
        _git(repo, "add", "src/a.ts")
        ok, _ = _check_single_commit_policy_isolation(base, "WORKTREE", cwd=str(repo))
    assert ok is True


def _merge_with_carried_src(merge_pkg: str, base_pkg: str | bytes = PKG_BASE) -> tuple[bool, str]:
    """Side branch carries `src/a.ts`; the merge commit itself edits `package.json` (both parents agree on it)."""
    with tempfile.TemporaryDirectory() as tmp:
        repo = _init_guard_repo(tmp)
        base = _commit_files(repo, "base", {"README.md": "x\n", "package.json": base_pkg})
        _git(repo, "checkout", "-q", "-b", "side")
        side = _commit_files(repo, "side", {"src/a.ts": "export {};\n"})
        _git(repo, "checkout", "-q", "-b", "main2", base)
        _commit_files(repo, "main", {"docs/b.md": "b\n"})
        _git(repo, "merge", "--no-ff", "--no-commit", "-q", side)
        merge = _commit_files(repo, "merge", {"package.json": merge_pkg})
        parents = _git(repo, "rev-list", "--parents", "-n", "1", merge).split()[1:]
        assert len(parents) == 2
        return _check_merge_commit_policy_isolation(merge, parents, cwd=str(repo))


def test_merge_package_json_scripts_with_src_fails() -> None:
    ok, msg = _merge_with_carried_src(PKG_BASE.replace('"eslint ."', '"true"'))
    assert ok is False
    assert "unconflicted governance edits" in msg
    assert "package.json" in msg


@pytest.mark.parametrize("base_pkg", [b"{\n", b"\xef\xbb\xbf" + PKG_BASE.encode("utf-8")])
def test_merge_package_json_scripts_with_src_fails_when_parents_share_malformed_blob(base_pkg: bytes) -> None:
    ok, msg = _merge_with_carried_src(PKG_BASE.replace('"eslint ."', '"true"'), base_pkg)
    assert ok is False
    assert "unconflicted governance edits" in msg
    assert "package.json" in msg


def test_merge_package_json_deps_with_src_passes() -> None:
    ok, _ = _merge_with_carried_src(PKG_BASE.replace('"a": "1"', '"a": "2"'))
    assert ok is True


def test_merge_introducing_package_json_scripts_and_src_fails() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        repo = _init_guard_repo(tmp)
        base = _commit_files(repo, "base", {"README.md": "x\n", "package.json": PKG_BASE})
        _git(repo, "checkout", "-q", "-b", "side")
        side = _commit_files(repo, "side", {"docs/a.md": "a\n"})
        _git(repo, "checkout", "-q", "-b", "main2", base)
        _commit_files(repo, "main", {"docs/b.md": "b\n"})
        _git(repo, "merge", "--no-ff", "--no-commit", "-q", side)
        merge = _commit_files(repo, "merge", {"package.json": PKG_BASE.replace('"eslint ."', '"true"'), "src/a.ts": "export {};\n"})
        parents = _git(repo, "rev-list", "--parents", "-n", "1", merge).split()[1:]
        ok, msg = _check_merge_commit_policy_isolation(merge, parents, cwd=str(repo))
    assert ok is False
    assert "mixed novel governance" in msg and "package.json" in msg


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


def test_e2e_with_playwright_config_fails() -> None:
    ok, msg = _isolation({"playwright.config.ts": "export default {};\n", "e2e/login.spec.ts": "export {};\n"})
    assert ok is False
    assert "playwright.config.ts" in msg


def test_e2e_alone_passes() -> None:
    ok, _ = _isolation({"e2e/login.spec.ts": "export {};\n"})
    assert ok is True


def _merge(side_files: dict[str, str], merge_files: dict[str, str], base_files: dict[str, str] | None = None) -> tuple[bool, str]:
    """Side branch commits `side_files`; the merge commit itself adds `merge_files`."""
    with tempfile.TemporaryDirectory() as tmp:
        repo = _init_guard_repo(tmp)
        base = _commit_files(repo, "base", {"README.md": "x\n", **(base_files or {})})
        _git(repo, "checkout", "-q", "-b", "side")
        side = _commit_files(repo, "side", side_files)
        _git(repo, "checkout", "-q", "-b", "main2", base)
        _commit_files(repo, "main", {"docs/b.md": "b\n"})
        _git(repo, "merge", "--no-ff", "--no-commit", "-q", side)
        merge = _commit_files(repo, "merge", merge_files)
        parents = _git(repo, "rev-list", "--parents", "-n", "1", merge).split()[1:]
        return _check_merge_commit_policy_isolation(merge, parents, cwd=str(repo))


def test_merge_novel_nested_tsconfig_only_passes() -> None:
    ok, msg = _merge({"docs/a.md": "a\n"}, {"packages/ui/tsconfig.json": "{}\n"})
    assert ok is True, msg


def test_merge_unconflicted_governance_with_side_nested_tsconfig_passes() -> None:
    ok, msg = _merge({"packages/ui/tsconfig.json": "{}\n"}, {"eslint.config.js": "export default [];\n"})
    assert ok is True, msg


UI_PKG_BASE = '{"name": "ui", "scripts": {"lint": "eslint ."}}\n'
UI_PKG_NEW = UI_PKG_BASE.replace('"eslint ."', '"true"')


def test_nested_package_json_scripts_only_passes_single_commit() -> None:
    ok, msg = _isolation({"packages/ui/package.json": UI_PKG_NEW}, {"packages/ui/package.json": UI_PKG_BASE})
    assert ok is True, msg


def test_nested_package_json_scripts_only_passes_merge() -> None:
    ok, msg = _merge({"docs/a.md": "a\n"}, {"packages/ui/package.json": UI_PKG_NEW}, {"packages/ui/package.json": UI_PKG_BASE})
    assert ok is True, msg
