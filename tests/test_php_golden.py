"""End-to-end PHP tamper rules through real git repositories (spec R9 rows 1-14, golden corpus in tests/golden/php)."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from guard_repo_harness import (
    _commit_files,
    _git,
    _init_guard_repo,
    _json_bytes,
    _run_baseline_guard,
    _run_scanner,
    _write_files,
)
from php_support import require_php

GOLDEN = Path(__file__).resolve().parent / "golden" / "php"
CASES = sorted(p.name for p in GOLDEN.iterdir() if (p / "case.json").is_file())
BASE_CONFIG = {"extra_slop_rules": [], "legacy_loc_waivers": [], "languages": ["php"]}
CONFIG_REL = "scripts/audit/audit_guard_config.json"


def _tree(root: Path) -> dict[str, str]:
    if not root.is_dir():
        return {}
    return {p.relative_to(root).as_posix(): p.read_text(encoding="utf-8") for p in sorted(root.rglob("*")) if p.is_file()}


def _config(meta: dict, side: str) -> dict:
    cfg = dict(BASE_CONFIG)
    if meta.get("profile") is False:
        del cfg["languages"]
    if meta.get(f"{side}_exceptions"):
        cfg["php_suppression_exceptions"] = meta[f"{side}_exceptions"]
    return cfg


def _apply(repo: Path, files: dict[str, str], previous: dict[str, str]) -> None:
    for rel in previous.keys() - files.keys():
        (repo / rel).unlink()
        _git(repo, "rm", "-q", "--cached", "--", rel)
    _write_files(repo, files)


def _build(tmp_path: Path, name: str) -> tuple[Path, str, str, dict]:
    case = GOLDEN / name
    meta = json.loads((case / "case.json").read_text(encoding="utf-8"))
    base_files, target_files = _tree(case / "base"), _tree(case / "target")
    (tmp_path / "repo").mkdir()
    repo = _init_guard_repo(str(tmp_path / "repo"))
    (repo / CONFIG_REL).write_bytes(_json_bytes(_config(meta, "base")))
    base = _commit_files(repo, "base", base_files, include_guards=True)
    _apply(repo, target_files, base_files)
    (repo / CONFIG_REL).write_bytes(_json_bytes(_config(meta, "target")))
    head = _commit_files(repo, "target", target_files, include_guards=True)
    return repo, base, head, meta


def _diff_scan(repo: Path, base: str, head: str, *extra: str, env: dict[str, str] | None = None):
    return _run_scanner(repo, "--diff-base", base, "--head-ref", head, *extra, extra_env=env)


def _php_lines(text: str) -> list[str]:
    return [ln for ln in text.splitlines() if "[php_" in ln]


@pytest.mark.parametrize("name", CASES)
def test_golden_case(tmp_path: Path, name: str) -> None:
    require_php()
    repo, base, head, meta = _build(tmp_path, name)
    if meta.get("require_rename"):
        assert any(ln.startswith("R") for ln in _git(repo, "diff", "-M", "--name-status", base, head).splitlines())
    proc = _diff_scan(repo, base, head)
    out = proc.stdout + proc.stderr
    assert proc.returncode == meta["exit"], out
    if meta["category"]:
        assert f"[{meta['category']}]" in proc.stderr, out
    else:
        assert not _php_lines(out), out


# SHA-256 of private lower-case words that must never appear in the corpus; digests keep the words out of the repo.
_FORBIDDEN_DIGESTS = frozenset(
    {
        "720036c8101f751b82cdba6e74fbd217419a2d478dd49f6d7ba6697ed3810ece",
        "fadd860425c3778a5ec808a50d1a8973775c19e8745769d44fdf4e43dd4c4f0c",
        "d98dec4fc3ce8e43d2efa55db7cfc2b0082da807a0effb098fb49babce5435a0",
        "e656f6cd1caedec309d0616246cfdcbc2c7cccfdd858440e0b47335d94001aab",
    }
)
_FORBIDDEN_LENGTHS = (6, 9)


def _has_forbidden_word(
    text: str,
    digests: frozenset[str] = _FORBIDDEN_DIGESTS,
    lengths: tuple[int, ...] = _FORBIDDEN_LENGTHS,
) -> bool:
    for size in lengths:
        for i in range(len(text) - size + 1):
            if hashlib.sha256(text[i : i + size].encode("utf-8")).hexdigest() in digests:
                return True
    return False


def _sha(word: str) -> str:
    return hashlib.sha256(word.encode("utf-8")).hexdigest()


@pytest.mark.parametrize("word", ["sample", "placehold"])  # one neutral word per checked length
def test_forbidden_word_check_detects_digested_words(word: str) -> None:
    assert sorted({len(w) for w in ("sample", "placehold")}) == sorted(_FORBIDDEN_LENGTHS)
    digests = _FORBIDDEN_DIGESTS | {_sha(word)}
    assert _has_forbidden_word(f"a fixture mentioning {word}co here", digests)
    assert not _has_forbidden_word("neutral fixture text", digests)
    assert not _has_forbidden_word(f"a fixture mentioning {word}co here")
    assert all(len(d) == 64 for d in _FORBIDDEN_DIGESTS)


def test_golden_corpus_is_neutral() -> None:
    for path in GOLDEN.rglob("*"):
        if path.is_file():
            text = path.read_text(encoding="utf-8").lower()
            assert "/users/" not in text and "@example" not in text, path
            assert not _has_forbidden_word(text), path


def test_profile_absent_no_php_findings(tmp_path: Path) -> None:  # row 12, second half
    repo, base, head, _ = _build(tmp_path, "12b_profile_absent")
    proc = _diff_scan(repo, base, head)
    assert proc.returncode == 0, proc.stderr
    assert not _php_lines(proc.stderr + proc.stdout)


def test_exception_added_in_same_change_has_no_effect(tmp_path: Path) -> None:  # row 10, second half
    require_php()
    repo, base, head, _ = _build(tmp_path, "10b_exception_added_same_change")
    cfg_at_head = json.loads(_git(repo, "show", f"{head}:{CONFIG_REL}"))
    assert cfg_at_head["php_suppression_exceptions"], "fixture must carry the exception in TARGET only"
    assert "php_suppression_exceptions" not in json.loads(_git(repo, "show", f"{base}:{CONFIG_REL}"))
    proc = _diff_scan(repo, base, head)
    assert proc.returncode == 1, proc.stderr
    assert "[php_suppression_added]" in proc.stderr


def test_exception_trusted_in_base_silences_only_matching_identity(tmp_path: Path) -> None:  # row 10, first half
    require_php()
    repo, base, head, _ = _build(tmp_path, "10a_exception_trusted_in_base")
    assert _diff_scan(repo, base, head).returncode == 0
    wider = "<?php\nnamespace Acme\\Shop\\Model;\nclass Foo {\n    public function run() {\n// phpcs:ignore Generic.Sample.Rule\na();\n// phpcs:ignore Other.Rule\nb();\n    }\n}\n"
    other = _commit_files(repo, "other code", {"app/code/Acme/Shop/Model/Foo.php": wider})
    proc = _diff_scan(repo, base, other)
    assert proc.returncode == 1 and proc.stderr.count("[php_suppression_added]") == 1, proc.stderr
    assert "Other.Rule" in proc.stderr


def test_php_parse_degraded_exit_2(tmp_path: Path) -> None:
    require_php()
    repo, base, head, _ = _build(tmp_path, "07a_parse_degraded")
    proc = _diff_scan(repo, base, head)
    assert proc.returncode == 2
    assert "Guard Analysis Error" in proc.stderr and "[php_parse_degraded]" in proc.stderr
    assert "AI Slop" not in proc.stderr


def test_staged_only_runs_php_rules(tmp_path: Path) -> None:
    require_php()
    case = GOLDEN / "01_rebound"
    (tmp_path / "repo").mkdir()
    repo = _init_guard_repo(str(tmp_path / "repo"))
    (repo / CONFIG_REL).write_bytes(_json_bytes(BASE_CONFIG))
    _commit_files(repo, "base", _tree(case / "base"), include_guards=True)
    rels = _write_files(repo, _tree(case / "target"))
    _git(repo, "add", *rels)
    proc = _run_scanner(repo, "--staged-only")
    assert proc.returncode == 1, proc.stderr
    assert "[php_suppression_rebound]" in proc.stderr


def test_commit_range_aggregate_runs_php_rules(tmp_path: Path) -> None:
    require_php()
    case = GOLDEN / "05_multiset_third"
    (tmp_path / "repo").mkdir()
    repo = _init_guard_repo(str(tmp_path / "repo"))
    (repo / CONFIG_REL).write_bytes(_json_bytes(BASE_CONFIG))
    base = _commit_files(repo, "base", _tree(case / "base"), include_guards=True)
    main = _git(repo, "rev-parse", "--abbrev-ref", "HEAD")
    _commit_files(repo, "add suppression", _tree(case / "target"))
    _commit_files(repo, "unrelated", {"docs/a.md": "a\n"})
    _git(repo, "checkout", "-q", "-b", "side", base)
    _commit_files(repo, "side", {"docs/b.md": "b\n"})
    _git(repo, "checkout", "-q", main)
    _git(repo, "merge", "--no-ff", "-q", "-m", "merge", "side")
    assert len(_git(repo, "rev-list", "--parents", "-n", "1", "HEAD").split()) == 3
    proc = _run_scanner(repo, "--commit-range", f"{base}..HEAD")
    assert proc.returncode == 1, proc.stderr
    assert len([ln for ln in proc.stderr.splitlines() if "[php_suppression_added]" in ln]) == 1, proc.stderr


def test_commit_range_per_commit_catches_add_then_remove_dedupes_aggregate(tmp_path: Path) -> None:
    require_php()
    case = GOLDEN / "05_multiset_third"
    (tmp_path / "repo").mkdir()
    repo = _init_guard_repo(str(tmp_path / "repo"))
    (repo / CONFIG_REL).write_bytes(_json_bytes(BASE_CONFIG))
    base = _commit_files(repo, "base", _tree(case / "base"), include_guards=True)
    _commit_files(repo, "add", _tree(case / "target"))
    _commit_files(repo, "remove", _tree(case / "base"))
    proc = _run_scanner(repo, "--commit-range", f"{base}..HEAD")
    assert proc.returncode == 1, proc.stderr
    assert proc.stderr.count("[php_suppression_added]") == 1


def test_output_is_deterministic_and_sorted(tmp_path: Path) -> None:
    require_php()
    (tmp_path / "repo").mkdir()
    repo = _init_guard_repo(str(tmp_path / "repo"))
    (repo / CONFIG_REL).write_bytes(_json_bytes(BASE_CONFIG))
    plain = "<?php\nnamespace Acme\\Shop\\Model;\nclass %s {\n    public function run() {\n%s\n    }\n}\n"
    names = ("Zed", "Alpha", "Mid")
    base = _commit_files(repo, "base", {f"app/code/Acme/Shop/Model/{n}.php": plain % (n, "a();") for n in names}, include_guards=True)
    head = _commit_files(repo, "head", {f"app/code/Acme/Shop/Model/{n}.php": plain % (n, "// phpcs:ignore A.B\na();") for n in names})
    runs = [_diff_scan(repo, base, head).stderr for _ in range(2)]
    assert runs[0] == runs[1]
    files = [ln.split(":")[0].strip() for ln in _php_lines(runs[0])]
    assert files == sorted(files) and len(files) == 3


def test_shadow_prints_php_fact_counts(tmp_path: Path) -> None:
    require_php()
    repo, base, head, _ = _build(tmp_path, "01_rebound")
    proc = _diff_scan(repo, base, head, env={"AGENT_RATCHET_SHADOW": "1"})
    assert "shadow: php app/code/Acme/Shop/Model/Foo.php" in proc.stderr
    assert "php.suppression.point=1" in proc.stderr


# --- row 11: configuration isolation (baseline-integrity) ---------------------------------------


def _isolation(tmp_path: Path, files: dict[str, str]):
    (tmp_path / "repo").mkdir()
    repo = _init_guard_repo(str(tmp_path / "repo"))
    _commit_files(repo, "base", {"README.md": "x\n"}, include_guards=True)
    rels = _write_files(repo, files)
    _git(repo, "add", *rels)
    return _run_baseline_guard(repo, "--enforce-policy-isolation")


def test_row11_phpstan_config_with_php_code_rejected(tmp_path: Path) -> None:
    proc = _isolation(tmp_path, {"phpstan.neon": "parameters:\n  level: 5\n", "app/code/Acme/Shop/Model/Foo.php": "<?php\n"})
    assert proc.returncode != 0
    assert "isolation" in (proc.stderr + proc.stdout).lower()


def test_row11_phpstan_config_alone_passes(tmp_path: Path) -> None:
    proc = _isolation(tmp_path, {"phpstan.neon": "parameters:\n  level: 5\n"})
    assert proc.returncode == 0, proc.stderr + proc.stdout


# --- row 14: external config -----------------------------------------------------------------------


def _external_repo(tmp_path: Path, name: str) -> tuple[Path, str, str]:
    case = GOLDEN / name
    (tmp_path / "repo").mkdir()
    repo = _init_guard_repo(str(tmp_path / "repo"))
    (repo / CONFIG_REL).unlink()
    base_files = _tree(case / "base")
    base = _commit_files(repo, "base", base_files)
    head = _commit_files(repo, "head", _tree(case / "target"))
    return repo, base, head


def _external_config(tmp_path: Path, payload: dict) -> Path:
    path = tmp_path / "cfg" / "c.json"
    path.parent.mkdir(exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")
    path.chmod(0o444)
    return path


@pytest.mark.parametrize("name,category", [("01_rebound", "php_suppression_rebound"), ("05_multiset_third", "php_suppression_added")])
def test_row14_external_config_blocks_rows_1_and_5(tmp_path: Path, name: str, category: str) -> None:
    require_php()
    repo, base, head = _external_repo(tmp_path, name)
    cfg = _external_config(tmp_path, {"languages": ["php"]})
    proc = _diff_scan(repo, base, head, "--config-file", str(cfg))
    assert proc.returncode == 1, proc.stderr
    assert f"[{category}]" in proc.stderr


def test_external_config_exceptions_apply_as_written(tmp_path: Path) -> None:
    require_php()
    meta = json.loads((GOLDEN / "10a_exception_trusted_in_base" / "case.json").read_text(encoding="utf-8"))
    repo, base, head = _external_repo(tmp_path, "10a_exception_trusted_in_base")
    cfg = _external_config(tmp_path, {"languages": ["php"], "php_suppression_exceptions": meta["base_exceptions"]})
    proc = _diff_scan(repo, base, head, "--config-file", str(cfg))
    assert proc.returncode == 0, proc.stderr
