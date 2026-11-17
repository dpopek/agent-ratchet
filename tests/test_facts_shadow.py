from __future__ import annotations

import pytest

from agent_ratchet import ai_slop_scanner
from agent_ratchet.facts import legacy, plugin
from agent_ratchet.ai_slop_scanner import scan_text_for_slop
from agent_ratchet.git_guard_io import SlopViolation

SHADOW_LINE = "agent-ratchet shadow:"
TS_NOCHECK = "// @ts-" + "nocheck\nexport const val = 42;\n"
JS_EMPTY_TESTS = "it('empty arrow', () => {});\nit('fn expr', function() {});\nit('real test', () => { expect(x).toBe(1); });\n"


class _Dummy:
    name = "dummy"

    def extract(self, blob, path, ctx):
        return []


@pytest.fixture
def clean_registry(monkeypatch):
    monkeypatch.setattr(plugin, "_REGISTRY", {})


def test_registry_roundtrip_and_duplicate(clean_registry):
    p = _Dummy()
    plugin.register_plugin(p)
    assert plugin.get_plugin("dummy") is p
    assert plugin.registered_plugins() == ("dummy",)
    with pytest.raises(ValueError):
        plugin.register_plugin(_Dummy())
    with pytest.raises(KeyError):
        plugin.get_plugin("nope")


def test_legacy_parity_on_conformance_fixtures():
    fixtures = {
        "ts_nocheck": scan_text_for_slop(TS_NOCHECK, "src/app.ts"),
        "js_empty_tests": scan_text_for_slop(JS_EMPTY_TESTS, "tests/widget.test.jsx"),
    }
    dup = SlopViolation("src/a.py", 3, "x_cat", "msg", "snip")
    fixtures["duplicates"] = [dup, dup, dup._replace(line=4)]
    checked = 0
    for name, vs in fixtures.items():
        assert vs, name
        assert legacy.shadow_report(vs).endswith("parity ok"), name
        assert legacy.shadow_report(vs) == f"agent-ratchet shadow: {len(vs)} facts, parity ok"
        checked += 1
    assert checked == 3


def _scan(tmp_path, monkeypatch, capsys, value):
    (tmp_path / "bad.ts").write_text(TS_NOCHECK, encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    if value is None:
        monkeypatch.delenv("AGENT_RATCHET_SHADOW", raising=False)
    else:
        monkeypatch.setenv("AGENT_RATCHET_SHADOW", value)
    capsys.readouterr()
    rc = ai_slop_scanner.main(["bad.ts"])
    cap = capsys.readouterr()
    return rc, cap.out, cap.err


@pytest.mark.parametrize("value", [None, "true", "0"])
def test_shadow_off_by_default_and_for_other_values(tmp_path, monkeypatch, capsys, value):
    rc, _, err = _scan(tmp_path, monkeypatch, capsys, value)
    assert rc == 1
    assert SHADOW_LINE not in err


def test_shadow_on_keeps_result(tmp_path, monkeypatch, capsys):
    rc0, out0, err0 = _scan(tmp_path, monkeypatch, capsys, None)
    rc1, out1, err1 = _scan(tmp_path, monkeypatch, capsys, "1")
    assert rc0 == rc1 == 1
    assert out0 == out1
    lines = [ln for ln in err1.splitlines() if ln.startswith(SHADOW_LINE)]
    assert len(lines) == 1 and lines[0].endswith("facts, parity ok")
    assert [ln for ln in err1.splitlines() if not ln.startswith(SHADOW_LINE)] == err0.splitlines()


def test_shadow_failure_never_changes_result(tmp_path, monkeypatch, capsys):
    rc0, out0, _ = _scan(tmp_path, monkeypatch, capsys, None)

    def boom(v):
        raise RuntimeError("x")

    monkeypatch.setattr(legacy, "violation_to_fact", boom)
    rc1, out1, err1 = _scan(tmp_path, monkeypatch, capsys, "1")
    assert (rc1, out1) == (rc0, out0)
    assert "agent-ratchet shadow: failed (RuntimeError)" in err1
