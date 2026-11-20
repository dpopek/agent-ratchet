"""Magento DI plugin comparison rules."""

from __future__ import annotations

from magento_support import require_magento

from agent_ratchet.magento.compare import DEGRADED, DISABLED, REMOVED, DiSide, compare_di
from agent_ratchet.magento.di import analyze_di

T = "Acme\\Target"


def plugin(name="p", target=T, disabled=None, type_="Acme\\P", sort=None) -> str:
    attrs = f'name="{name}"'
    if type_:
        attrs += f' type="{type_}"'
    if disabled is not None:
        attrs += f' disabled="{disabled}"'
    if sort is not None:
        attrs += f' sortOrder="{sort}"'
    return f'<type name="{target}"><plugin {attrs}/></type>'


def side(xml: str, module="V/M", area="global") -> DiSide:
    require_magento()
    root = f"app/code/{module}"
    path = f"{root}/etc/di.xml" if area == "global" else f"{root}/etc/{area}/di.xml"
    return DiSide(path, analyze_di(f"<config>{xml}</config>".encode(), path, root, area))


def cats(findings) -> list[str]:
    return [f.category for f in findings]


def test_disabled_added_on_existing():
    out = compare_di([side(plugin())], [side(plugin(disabled="true"))], frozenset(), [])
    assert cats(out) == [DISABLED]
    assert out[0].message == f"Magento DI plugin disabled: global {T} p"
    assert out[0].snippet == f"global {T} p"
    assert out[0].file == "app/code/V/M/etc/di.xml" and out[0].line == 1


def test_disabled_override_in_other_module_adminhtml():
    out = compare_di(
        [side(plugin())], [side(plugin()), side(plugin(disabled="true"), "V/O", "adminhtml")], frozenset(), []
    )
    assert cats(out) == [DISABLED]
    assert out[0].file == "app/code/V/O/etc/adminhtml/di.xml"


def test_already_disabled_moved_is_clean():
    out = compare_di([side(plugin(disabled="true"))], [side(plugin(disabled="true"), "V/O")], frozenset(), [])
    assert out == []


def test_deleted_is_removed():
    out = compare_di([side(plugin())], [side("")], frozenset(), [])
    assert cats(out) == [REMOVED]
    assert out[0].file == "app/code/V/M/etc/di.xml"
    assert out[0].message == f"Magento DI plugin removed: global {T} p"


def test_moved_to_other_module_same_area():
    assert compare_di([side(plugin())], [side(plugin(), "V/O")], frozenset(), []) == []


def test_frontend_to_global_is_clean():
    assert compare_di([side(plugin(), area="frontend")], [side(plugin())], frozenset(), []) == []


def test_global_to_frontend_is_removed_once():
    out = compare_di([side(plugin())], [side(plugin(), area="frontend")], frozenset(), [])
    assert cats(out) == [REMOVED]
    assert "global" in out[0].message


def test_active_to_disabled_in_other_module_reports_both():
    out = compare_di([side(plugin())], [side(plugin(disabled="true"), "V/O")], frozenset(), [])
    assert sorted(cats(out)) == [DISABLED, REMOVED]


def test_disabled_removed_without_finding():
    assert compare_di([side(plugin(disabled="true"))], [side("")], frozenset(), []) == []


def test_area_scoping_disable_one_area_only():
    base = [side(plugin(), area="frontend"), side(plugin(), area="webapi_soap")]
    target = [side(plugin(), area="frontend"), side(plugin(disabled="true"), area="webapi_soap")]
    out = compare_di(base, target, frozenset(), [])
    assert cats(out) == [DISABLED]
    assert "webapi_soap" in out[0].message


def test_benign_changes_pass():
    base = [side(plugin(sort=1) + '<preference for="A" type="B"/>')]
    assert compare_di(base, [side(plugin(type_="Acme\\Q", sort=9) + '<preference for="A" type="C"/>')], frozenset(), []) == []
    assert compare_di(base, [side(plugin(sort=1) + plugin(name="q"))], frozenset(), []) == []
    assert compare_di(base, [side(plugin(sort=1))], frozenset(), []) == []
    assert compare_di([side(plugin(disabled="true"))], [side(plugin())], frozenset(), []) == []


def test_module_removal():
    gone = frozenset({"app/code/V/M"})
    assert compare_di([side(plugin())], [side("")], gone, []) == []
    assert cats(compare_di([side(plugin())], [side("")], frozenset(), [])) == [REMOVED]


def test_exceptions():
    exc = [{"area": "global", "target": T, "plugin": "p", "reason": "r"}]
    assert compare_di([side(plugin())], [side(plugin(disabled="true"))], frozenset(), exc) == []
    assert compare_di([side(plugin())], [side("")], frozenset(), exc) == []
    other = [{"area": "frontend", "target": T, "plugin": "p", "reason": "r"}]
    assert cats(compare_di([side(plugin())], [side("")], frozenset(), other)) == [REMOVED]


def test_unreadable_target_is_degraded_never_silenced():
    require_magento()
    path = "app/code/V/M/etc/di.xml"
    bad = DiSide(path, analyze_di(b"<config>", path, "app/code/V/M", "global"))
    exc = [{"area": "global", "target": T, "plugin": "p", "reason": "r"}]
    out = compare_di([side(plugin())], [bad], frozenset(), exc)
    assert cats(out) == [DEGRADED]
    assert out[0].file == path and out[0].snippet == bad.analysis.unreadable
    assert out[0].message == f"Magento XML not analyzable ({bad.analysis.unreadable})"


def test_unreadable_base_contributes_nothing():
    require_magento()
    path = "app/code/V/M/etc/di.xml"
    bad = DiSide(path, analyze_di(b"<config>", path, "app/code/V/M", "global"))
    assert compare_di([bad], [side("")], frozenset(), []) == []
