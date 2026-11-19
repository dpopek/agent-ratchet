from __future__ import annotations

import importlib.metadata
import io
import json
from contextlib import redirect_stderr, redirect_stdout

import pytest

from agent_ratchet import ai_slop_scanner, cli


class _FakeDistribution:
    def __init__(self, commit: str) -> None:
        self._payload = json.dumps({"url": "https://example.invalid/agent-ratchet", "vcs_info": {"vcs": "git", "commit_id": commit}})

    def read_text(self, filename: str) -> str | None:
        return self._payload if filename == "direct_url.json" else None


def _capture_help(func, argv: list[str]) -> tuple[int, str]:
    out = io.StringIO()
    with redirect_stdout(out), redirect_stderr(io.StringIO()):
        try:
            rc = func(argv)
        except SystemExit as exc:
            rc = int(exc.code or 0)
    return rc, out.getvalue()


def test_expect_sha_mismatch_exits_3(monkeypatch, capsys) -> None:
    monkeypatch.setattr(importlib.metadata, "distribution", lambda name: _FakeDistribution("a" * 40))
    rc = cli.main(["--expect-sha", "b" * 40, "version"])
    assert rc == 3
    assert capsys.readouterr().err.strip() == f"agent-ratchet: installed {'a' * 40} != lock {'b' * 40}"


def test_expect_sha_without_vcs_install_exits_3(monkeypatch, capsys) -> None:
    def _raise(name: str) -> None:
        raise importlib.metadata.PackageNotFoundError(name)

    monkeypatch.setattr(importlib.metadata, "distribution", _raise)
    assert cli.main(["--expect-sha", "b" * 40, "version"]) == 3
    assert "installed None != lock" in capsys.readouterr().err


def test_expect_sha_match_proceeds(monkeypatch, capsys) -> None:
    monkeypatch.setattr(importlib.metadata, "distribution", lambda name: _FakeDistribution("a" * 40))
    assert cli.main(["--expect-sha", "a" * 40, "version", "--sha"]) == 0
    assert capsys.readouterr().out == "a" * 40 + "\n"


@pytest.mark.parametrize(
    "argv",
    [
        ["--expect-sha", "a" * 40, "version", "--expect-sha", "b" * 40],
        ["--expect-sha", "a" * 40, "scan", f"--expect-sha={'b' * 40}"],
        [f"--expect-sha={'a' * 40}", f"--expect-sha={'a' * 40}", "version"],
    ],
    ids=["space_after_subcommand", "equals_after_subcommand", "equals_twice"],
)
def test_expect_sha_given_twice_exits_3(monkeypatch, capsys, argv: list[str]) -> None:
    monkeypatch.setattr(importlib.metadata, "distribution", lambda name: _FakeDistribution("b" * 40))
    assert cli.main(argv) == 3
    assert capsys.readouterr().err.strip() == "agent-ratchet: --expect-sha given more than once"


def test_scan_passes_argv_through() -> None:
    direct_rc, direct_out = _capture_help(ai_slop_scanner.main, ["--help"])
    cli_rc, cli_out = _capture_help(cli.main, ["scan", "--help"])
    assert cli_rc == direct_rc == 0
    assert cli_out == direct_out
    assert "usage:" in cli_out


def test_file_scan_states_its_limited_scope_on_stderr(tmp_path, monkeypatch, capsys) -> None:
    (tmp_path / "clean.py").write_text("def f(x):\n    return x\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    assert ai_slop_scanner.main(["clean.py"]) == 0
    captured = capsys.readouterr()
    assert captured.out == "✅ Scanned files — zero slop violations detected.\n"
    assert captured.err == (
        "note: file scan runs text rules and syntax checks only; use --staged-only, --diff-base or --commit-range "
        "for AST, topology and test-integrity checks\n"
    )


def test_file_scan_reports_python_syntax_error_with_exit_2(tmp_path, monkeypatch, capsys) -> None:
    (tmp_path / "broken.py").write_text("def f(:\n    return 1\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    assert ai_slop_scanner.main(["broken.py"]) == 2
    assert "broken.py:1 -> [syntax_error]" in capsys.readouterr().err


@pytest.mark.parametrize("sub", ["scan", "baseline-integrity"])
def test_help_carries_no_stale_version(sub: str) -> None:
    rc, out = _capture_help(cli.main, [sub, "--help"])
    assert rc == 0
    assert "2.3.3" not in out


def test_unknown_subcommand_is_rejected() -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["bogus"])
    assert exc.value.code == 2
