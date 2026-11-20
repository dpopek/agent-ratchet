"""End-to-end Magento di.xml rules through real git repositories (spec M7, golden corpus in tests/golden/magento)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from guard_repo_harness import _commit_files, _git, _init_guard_repo, _json_bytes, _run_scanner, _write_files
from magento_support import require_magento
from test_php_golden import _has_forbidden_word

GOLDEN = Path(__file__).resolve().parent / "golden" / "magento"
CASES = sorted(p.name for p in GOLDEN.iterdir() if (p / "case.json").is_file())
BASE_CONFIG = {"extra_slop_rules": [], "legacy_loc_waivers": [], "languages": ["php"], "frameworks": ["magento"]}
CONFIG_REL = "scripts/audit/audit_guard_config.json"
DI_A = "app/code/Acme/ModA/etc/di.xml"


def _tree(root: Path) -> dict[str, str]:
    if not root.is_dir():
        return {}
    return {p.relative_to(root).as_posix(): p.read_text(encoding="utf-8") for p in sorted(root.rglob("*")) if p.is_file()}


def _config(meta: dict, side: str) -> dict:
    cfg = dict(BASE_CONFIG)
    if meta.get("profile") == "php":
        del cfg["frameworks"]
    if meta.get(f"{side}_exceptions"):
        cfg["magento_di_exceptions"] = meta[f"{side}_exceptions"]
    return cfg


def _apply(repo: Path, files: dict[str, str], previous: dict[str, str]) -> None:
    for rel in previous.keys() - files.keys():
        (repo / rel).unlink()
        _git(repo, "rm", "-q", "--cached", "--", rel)
    _write_files(repo, files)


def _new_repo(tmp_path: Path) -> Path:
    (tmp_path / "repo").mkdir()
    return _init_guard_repo(str(tmp_path / "repo"))


def _build(tmp_path: Path, name: str) -> tuple[Path, str, str, dict]:
    case = GOLDEN / name
    meta = json.loads((case / "case.json").read_text(encoding="utf-8"))
    base_files, target_files = _tree(case / "base"), _tree(case / "target")
    repo = _new_repo(tmp_path)
    (repo / CONFIG_REL).write_bytes(_json_bytes(_config(meta, "base")))
    base = _commit_files(repo, "base", base_files, include_guards=True)
    _apply(repo, target_files, base_files)
    (repo / CONFIG_REL).write_bytes(_json_bytes(_config(meta, "target")))
    head = _commit_files(repo, "target", target_files, include_guards=True)
    return repo, base, head, meta


def _diff_scan(repo: Path, base: str, head: str, env: dict[str, str] | None = None):
    return _run_scanner(repo, "--diff-base", base, "--head-ref", head, extra_env=env)


def _magento_lines(text: str) -> list[str]:
    return [ln for ln in text.splitlines() if "[magento_" in ln]


@pytest.mark.parametrize("name", CASES)
def test_golden_case(tmp_path: Path, name: str) -> None:
    require_magento()
    repo, base, head, meta = _build(tmp_path, name)
    if meta.get("require_rename"):
        assert any(ln.startswith("R") for ln in _git(repo, "diff", "-M", "--name-status", base, head).splitlines())
    proc = _diff_scan(repo, base, head)
    out = proc.stdout + proc.stderr
    assert proc.returncode == meta["exit"], out
    lines = _magento_lines(out)
    if meta["category"]:
        assert lines and all(f"[{meta['category']}]" in ln for ln in lines), out
        assert len(lines) == meta.get("count", len(lines)), out
        assert meta.get("snippet", "") in proc.stderr, out
    else:
        assert not lines, out


def test_corpus_has_no_forbidden_words() -> None:
    for path in GOLDEN.rglob("*"):
        if path.is_file():
            text = path.read_text(encoding="utf-8").lower()
            assert "/users/" not in text and "@example" not in text, path
            assert not _has_forbidden_word(text), path


def test_commit_range_dedupes(tmp_path: Path) -> None:
    require_magento()
    case = GOLDEN / "01_disabled_added"
    repo = _new_repo(tmp_path)
    (repo / CONFIG_REL).write_bytes(_json_bytes(BASE_CONFIG))
    base = _commit_files(repo, "base", _tree(case / "base"), include_guards=True)
    _commit_files(repo, "disable", _tree(case / "target"))
    _commit_files(repo, "unrelated", {"docs/a.md": "a\n"})
    proc = _run_scanner(repo, "--commit-range", f"{base}..HEAD")
    assert proc.returncode == 1, proc.stderr
    assert len([ln for ln in proc.stderr.splitlines() if "[magento_di_plugin_disabled]" in ln]) == 1, proc.stderr


def test_shadow_counts(tmp_path: Path) -> None:
    require_magento()
    repo, base, head, _ = _build(tmp_path, "07_preferences")
    proc = _diff_scan(repo, base, head, env={"AGENT_RATCHET_SHADOW": "1"})
    assert f"agent-ratchet shadow: magento {DI_A}: plugin=1 preference=1" in proc.stderr, proc.stderr
    assert "agent-ratchet shadow: magento app/code/Acme/ModA/etc/frontend/di.xml: plugin=0 preference=1" in proc.stderr
    assert "shadow: magento" not in _diff_scan(repo, base, head).stderr
