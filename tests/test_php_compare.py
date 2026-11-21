"""PHP tamper comparison on pure blobs (spec R6, acceptance rows 1-10 as unit cases)."""

from __future__ import annotations

import pytest
from php_support import require_php

PATH = "app/code/V/M/Model/X.php"
TEST_PATH = "app/code/V/M/Test/Unit/XTest.php"


def _cats(base, target, *, base_path=PATH, target_path=None, exceptions=(), renamed=False):
    require_php()
    from agent_ratchet.php.compare import compare_php_entry

    enc = lambda s: s.encode() if isinstance(s, str) else s
    found = compare_php_entry(
        None if base is None else enc(base),
        None if target is None else enc(target),
        base_path,
        target_path or PATH,
        exceptions,
        renamed=renamed,
    )
    return [v.category for v in found]


def _m(body: str, name: str = "run", extra: str = "") -> str:
    return f"<?php\nnamespace V\\M;\nclass X {{\n    public function {name}() {{\n{body}\n    }}\n{extra}}}\n"


def _t(body: str, head: str = "", doc: str = "") -> str:
    return (
        "<?php\nnamespace V\\M\\Test;\nuse PHPUnit\\Framework\\TestCase;\nuse PHPUnit\\Framework\\Attributes\\DataProvider;\n"
        f"class XTest extends TestCase\n{{\n{doc}{head}    public function testIt(): void {{\n{body}\n    }}\n}}\n"
    )


# --- spec R9 rows 1-6 ------------------------------------------------------------------------


def test_row1_ignore_moved_to_another_statement_is_rebound() -> None:
    base = _m("$a = foo();\n// @phpstan-ignore foo.bar\n$b = bar($a);\nbaz($b);")
    target = _m("$a = foo();\n$b = bar($a);\n// @phpstan-ignore foo.bar\nbaz($b);")
    assert _cats(base, target) == ["php_suppression_rebound"]


def test_row2_directive_moved_with_its_statement_passes() -> None:
    base = _m("// @phpstan-ignore foo.bar\n$b = bar($a);\nbaz();")
    target = _m("baz();\n\n\n// @phpstan-ignore foo.bar\n$b   =   bar( $a );")
    assert _cats(base, target) == []


def test_row3_window_pulls_in_existing_statement() -> None:
    base = _m("y();\n// phpcs:disable Generic.X.Y\na();\n// phpcs:enable Generic.X.Y\nz();")
    target = _m("// phpcs:disable Generic.X.Y\ny();\na();\n// phpcs:enable Generic.X.Y\nz();")
    assert _cats(base, target) == ["php_suppression_range_expanded"]


# --- window pull-in semantics (R6 `php_suppression_range_expanded`, amended 19.11) -------------

_WIN = "// phpcs:disable Generic.X.Y\n"
_END = "// phpcs:enable Generic.X.Y\n"


def _cls(body: str) -> str:
    return f"<?php\nnamespace V\\M;\n// phpcs:disable Generic.X.Y\nclass X {{\n{body}}}\n"


def test_new_code_under_unclosed_window_passes() -> None:
    base = _cls("    public function run() {\n        a();\n        b();\n    }\n")
    target = _cls(
        "    public function run() {\n        a(1);\n        b();\n        c();\n    }\n"
        "    public function more() {\n        d();\n    }\n"
    )
    assert _cats(base, target) == []


def test_edit_under_closed_window_passes() -> None:
    base = _m(_WIN + "a();\n" + _END + "z();")
    assert _cats(base, _m(_WIN + "a(1);\nb();\n" + _END + "z();")) == []


def test_disable_moved_over_existing_statement_flags() -> None:
    base = _m("y();\n" + _WIN + "a();\n" + _END + "z();")
    assert _cats(base, _m(_WIN + "y();\na();\n" + _END + "z();")) == ["php_suppression_range_expanded"]


def test_enable_moved_down_over_existing_statement_flags() -> None:
    base = _m(_WIN + "a();\n" + _END + "z();")
    assert _cats(base, _m(_WIN + "a();\nz();\n" + _END)) == ["php_suppression_range_expanded"]


def test_enable_removed_still_flags() -> None:
    base = _m(_WIN + "a();\n" + _END)
    assert _cats(base, _m(_WIN + "a();")) == ["php_suppression_range_expanded"]


def test_new_window_identity_still_flags() -> None:
    base = _m(_WIN + "a();\n" + _END + "z();")
    target = _m(_WIN + "a();\n" + _END + "// phpcs:disable Other.X.Y\nz();\n// phpcs:enable Other.X.Y")
    assert _cats(base, target) == ["php_suppression_range_expanded"]


def test_codes_widened_still_flags() -> None:
    base = _m(_WIN + "a();\n" + _END)
    assert _cats(base, _m("// phpcs:disable Generic.X.Y, Other.X.Y\na();\n// phpcs:enable")) == [
        "php_suppression_range_expanded"
    ]


def test_duplicate_statement_pulled_in_flags() -> None:
    base = _m("$a++;\n" + _WIN + "$a++;\n" + _END)
    assert _cats(base, _m(_WIN + "$a++;\n$a++;\n" + _END)) == ["php_suppression_range_expanded"]


def test_duplicate_new_statement_under_window_passes() -> None:
    base = _m(_WIN + "$a++;\n" + _END)
    assert _cats(base, _m(_WIN + "$a++;\n$a++;\n" + _END)) == []


def test_row4_deleting_enable_unclosed_window() -> None:
    base = _m("// phpcs:disable Generic.X.Y\na();\n// phpcs:enable Generic.X.Y\nz();")
    target = _m("// phpcs:disable Generic.X.Y\na();\nz();")
    assert _cats(base, target) == ["php_suppression_range_expanded"]


def test_enable_with_space_separated_codes_does_not_close_window() -> None:
    base = _m("// phpcs:disable A.B\na();\n// phpcs:enable A.B\nz();")
    target = _m("// phpcs:disable A.B\na();\n// phpcs:enable A.B C.D\nz();\nadded();")
    assert _cats(base, target) == ["php_suppression_range_expanded"]


def test_mid_text_enable_does_not_close_window() -> None:
    base = _m("// phpcs:disable A.B\na();\n// phpcs:enable A.B\nz();")
    target = _m("// phpcs:disable A.B\na();\n// note phpcs:enable A.B\nz();\nadded();")
    assert _cats(base, target) == ["php_suppression_range_expanded"]


@pytest.mark.parametrize("space", [" ", "\u000c"])
def test_enable_after_unicode_space_does_not_close_window(space) -> None:
    base = _m("// phpcs:disable A.B\na();\n// phpcs:enable A.B\nz();")
    target = _m(f"// phpcs:disable A.B\na();\n//{space}phpcs:enable A.B\nz();")
    assert _cats(base, target) == ["php_suppression_range_expanded"]


def test_row5_third_identical_ignore_is_added() -> None:
    two = "// phpcs:ignore Generic.X.Y\na();\n// phpcs:ignore Generic.X.Y\nb();"
    assert _cats(_m(two), _m(two + "\n// phpcs:ignore Generic.X.Y\nc();")) == ["php_suppression_added"]


def test_row6_legacy_forms_added() -> None:
    base = _m("a();")
    target = "<?php\n/* @codingStandardsIgnoreFile */\n" + _m("// phpcs:disabled\na();")[len("<?php\n") :]
    # `phpcs:disabled` is a real `disable` to PHPCS (prefix match), so it is a new window like any other
    assert _cats(base, target) == ["php_suppression_added", "php_suppression_range_expanded"]
    assert _cats(base, _m("// phpcs:disabled\na();")) == ["php_suppression_range_expanded"]


def test_added_suppression_with_unresolved_anchor_also_flags_unknown() -> None:
    target = _m("a();\n// @phpstan-ignore foo.bar")
    assert _cats(_m("a();"), target) == ["php_suppression_added", "php_suppression_anchor_unknown"]


def test_preexisting_unresolved_anchor_does_not_block() -> None:
    both = _m("a();\n// @phpstan-ignore foo.bar")
    assert _cats(both, both.replace("a();", "a(); b();")) == []


# --- passes ----------------------------------------------------------------------------------


def test_removed_suppression_passes() -> None:
    base = _m("// phpcs:ignore A.B\na();\n// phpcs:disable\nb();\n// phpcs:enable")
    assert _cats(base, _m("a();\nb();")) == []


def test_narrowed_codes_passes() -> None:
    base = _m("// phpcs:ignore A.B, C.D\na();\n// phpcs:disable A.B, C.D\nb();\n// phpcs:enable")
    target = _m("// phpcs:ignore A.B\na();\n// phpcs:disable A.B\nb();\n// phpcs:enable")
    assert _cats(base, target) == []
    assert _cats(_m("// phpcs:ignore\na();"), _m("// phpcs:ignore A.B\na();")) == []


def test_widened_codes_is_added() -> None:
    assert _cats(_m("// phpcs:ignore A.B\na();"), _m("// phpcs:ignore\na();")) == ["php_suppression_added"]
    assert _cats(_m("// phpcs:ignore A.B\na();"), _m("// phpcs:ignore A.B, C.D\na();")) == ["php_suppression_added"]
    base = _m("// phpcs:disable A.B\na();\n// phpcs:enable")
    assert _cats(base, _m("// phpcs:disable\na();\n// phpcs:enable")) == ["php_suppression_range_expanded"]


def test_file_suppression_added_and_narrowed() -> None:
    plain = _m("a();")
    assert _cats(plain, "<?php\n// phpcs:ignoreFile\n" + plain[6:]) == ["php_suppression_added"]
    wide = "<?php\n// phpcs:ignoreFile\n" + plain[6:]
    assert _cats(wide, wide) == []


def test_new_window_identity_is_expanded() -> None:
    assert _cats(_m("a();"), _m("// phpcs:disable X.Y\na();\n// phpcs:enable")) == ["php_suppression_range_expanded"]


# --- row 7: parse gaps -----------------------------------------------------------------------

_BROKEN = "<?php\nnamespace V\\M;\nclass X {\n    public function a() {\n        return %s;\n    }\n    public function b() {\n        return foo(;\n    }\n}\n"
_CLEAN = "<?php\nnamespace V\\M;\nclass X {\n    public function a() {\n        return %s;\n    }\n    public function b() {\n        return foo();\n    }\n}\n"


def test_new_parse_gap_in_changed_method_is_degraded() -> None:
    assert _cats(_CLEAN % "1", _BROKEN % "1") == ["php_parse_degraded"]
    assert _cats(None, _BROKEN % "1") == ["php_parse_degraded"]


def test_preexisting_parse_gap_in_untouched_method_passes() -> None:
    assert _cats(_BROKEN % "1", _BROKEN % "2") == []
    assert _cats(_BROKEN % "1", _BROKEN % "1") == []


def test_changed_text_of_already_broken_symbol_is_degraded() -> None:
    assert _cats(_BROKEN % "1", (_BROKEN % "1").replace("foo(;", "foo(1;")) == ["php_parse_degraded"]


def test_degraded_symbol_facts_contribute_no_findings() -> None:
    base = _m("// phpcs:ignore A.B\na();")
    target = _m("// phpcs:ignore A.B\n// phpcs:ignore C.D\na(;")
    assert _cats(base, target) == ["php_parse_degraded"]


def test_zero_width_missing_token_at_symbol_end_is_inside_symbol() -> None:
    require_php()
    from agent_ratchet.php.extract import analyze

    src = b"<?php\nclass X {\n    public function a() {\n        return 1;\n    }\n"  # class never closed
    an = analyze(src, PATH)
    gap = [f for f in an.facts if f.kind == "php.parse_gap"]
    method_end = src.index(b"    }\n") + len(b"    }")
    assert [f.origin.byte_span for f in gap] == [(method_end, method_end)]  # zero width, exactly at the method's end
    assert set(an.gap_hashes) == {"X::a"}  # inclusive end: the innermost symbol ending there owns the gap
    assert _cats(None, src) == ["php_parse_degraded"]


def test_non_utf8_identifier_is_degraded_not_crash() -> None:
    bad = b"<?php\nnamespace A\\B;\nclass C\xff {\n    public function m() {\n        // phpcs:ignore\n        run();\n    }\n}\n"
    assert _cats(None, bad) == ["php_parse_degraded"]
    assert _cats(b"<?php\nclass C {}\n", bad) == ["php_parse_degraded"]
    assert _cats(bad, bad) == []
    assert _cats(b"<?php\nclass C {}\n", bad.replace(b"C\xff", b"C\xfe")) == ["php_parse_degraded"]
    assert _cats(bad.replace(b"C\xff", b"C\xfe"), bad) == ["php_parse_degraded"]  # TARGET stays strict


# --- 4.1.3: an unreadable BASE does not block its own fix or deletion (audit D2) --------------------

_BAD_TEST = _t("$this->assertTrue(true);").encode().replace(b"class XTest", b"class X\xffTest")
_FIXED_TEST = _BAD_TEST.replace(b"X\xffTest", b"XTest")


def test_fixing_a_non_utf8_base_passes() -> None:
    bad = b"<?php\nnamespace A\\B;\nclass C\xff {\n    public function m() {\n        run();\n    }\n}\n"
    assert _cats(bad, bad.replace(b"C\xff", b"C")) == []
    assert _cats(_BAD_TEST, _FIXED_TEST, base_path=TEST_PATH, target_path=TEST_PATH) == []


def test_deleting_a_non_utf8_base_without_tests_passes() -> None:
    assert _cats(b"<?php\nclass C\xff {}\n", None) == []


def test_non_utf8_base_still_reports_test_removal() -> None:
    assert _cats(_BAD_TEST, None, base_path=TEST_PATH, target_path=TEST_PATH) == ["php_test_removed"]
    dropped = _FIXED_TEST.replace(b"$this->assertTrue(true);", b"").replace(b"testIt", b"helperIt")
    assert "php_test_removed" in _cats(_BAD_TEST, dropped, base_path=TEST_PATH, target_path=TEST_PATH)


def test_non_utf8_base_does_not_hide_an_added_suppression() -> None:
    bad = b"<?php\nnamespace A\\B;\nclass C\xff {\n    public function m() {\n        run();\n    }\n}\n"
    fixed = bad.replace(b"C\xff", b"C").replace(b"        run();", b"        // phpcs:ignore\n        run();")
    assert _cats(bad, fixed) == ["php_suppression_added"]


def test_non_utf8_in_test_class_name_is_degraded() -> None:
    bad = _t("$this->assertTrue(1);").encode().replace(b"testIt", b"test\xffIt")
    assert _cats(None, bad, target_path=TEST_PATH) == ["php_parse_degraded"]


# --- row 8: test weakening -------------------------------------------------------------------

_FULL = "$this->assertTrue(true);\n$this->assertSame(1, 1);\n$m->expects($this->once())->method('a');\n$this->expectException(\\Foo::class);"
_DOC = "    /**\n     * @dataProvider prov\n     */\n"
_ATTR = "    #[DataProvider('prov')]\n"


@pytest.mark.parametrize(
    "base, target",
    [
        (_t(_FULL), _t(_FULL.replace("$this->assertSame(1, 1);\n", ""))),
        (_t(_FULL), _t(_FULL.replace("$m->expects($this->once())->method('a');\n", ""))),
        (_t(_FULL), _t(_FULL.replace("$this->expectException(\\Foo::class);", ""))),
        (_t(_FULL), _t(_FULL + "\n$this->markTestSkipped('later');")),
        (_t(_FULL), _t(_FULL + "\n$this->markTestIncomplete('later');")),
        (_t(_FULL, doc=_DOC), _t(_FULL)),
        (_t(_FULL, head=_ATTR), _t(_FULL)),
    ],
)
def test_row8_test_weakening(base: str, target: str) -> None:
    assert _cats(base, target, base_path=TEST_PATH, target_path=TEST_PATH) == ["php_test_weakened"]


def test_added_assertion_passes() -> None:
    base = _t(_FULL, doc=_DOC)
    target = _t(_FULL + "\n$this->assertNull(null);\n$m->expects($this->never())->method('z');", doc=_DOC)
    assert _cats(base, target, base_path=TEST_PATH, target_path=TEST_PATH) == []


def test_tests_in_phtml_and_non_test_classes_are_ignored() -> None:
    plain = "<?php\nclass Y { public function testA() { $this->assertTrue(1); } }\n"
    assert _cats(plain, plain.replace("$this->assertTrue(1);", "")) == []


# --- row 9: removal vs rename ----------------------------------------------------------------


def test_row9_deleted_test_method_is_removed() -> None:
    other = "    public function testOther(): void {\n        $this->assertSame(2, 2);\n    }\n"
    base = _t(_FULL).replace("    public function testIt", other + "    public function testIt")
    assert _cats(base, _t(_FULL), base_path=TEST_PATH, target_path=TEST_PATH) == ["php_test_removed"]


def test_row9_renamed_test_with_identical_body_passes() -> None:
    base = _t(_FULL)
    assert _cats(base, base.replace("testIt", "testRenamed"), base_path=TEST_PATH, target_path=TEST_PATH) == []


def test_row9_file_move_passes() -> None:
    base = _t(_FULL)
    moved = "app/code/V/M/Test/Unit/Sub/XTest.php"
    assert _cats(base, base, base_path=TEST_PATH, target_path=moved) == []
    assert _cats(base, base.replace("assertTrue", "assertFalse"), base_path=TEST_PATH, target_path=moved) == []
    weaker = base.replace("$this->assertSame(1, 1);\n", "")
    assert _cats(base, weaker, base_path=TEST_PATH, target_path=moved) == ["php_test_weakened"]


def test_deleted_test_file_blocks_unless_moved() -> None:
    require_php()
    from agent_ratchet.php.compare import compare_php_entry, compare_php_tests_across
    from agent_ratchet.php.extract import PhpPlugin

    src = _t(_FULL).encode()
    found = compare_php_entry(src, None, TEST_PATH, TEST_PATH, ())
    assert [v.category for v in found] == ["php_test_removed"]
    assert found[0].file == TEST_PATH
    plugin = PhpPlugin()
    removed = [f for f in plugin.extract(src, TEST_PATH, {}) if f.kind == "php.test"]
    elsewhere = [f for f in plugin.extract(src.replace(b"XTest", b"MovedTest"), "app/code/V/M/Test/Unit/Moved.php", {}) if f.kind == "php.test"]
    assert compare_php_tests_across(removed, elsewhere) == []
    assert [v.category for v in compare_php_tests_across(removed, [])] == ["php_test_removed"]
    weaker = [f for f in plugin.extract(src.replace(b"$this->assertSame(1, 1);", b""), "x/Y.php", {}) if f.kind == "php.test"]
    assert [v.category for v in compare_php_tests_across(removed, weaker)] == ["php_test_removed"]


# --- row 10: trusted exceptions ---------------------------------------------------------------


def _exc(**over):
    return {"path": PATH, "symbol": "V\\M\\X::run", "tool": "phpcs", "codes": ["Generic.X.Y"], "reason": "legacy", **over}


def test_row10_exception_silences_added_rebound_and_range() -> None:
    target = _m("// phpcs:ignore Generic.X.Y\na();")
    assert _cats(_m("a();"), target) == ["php_suppression_added"]
    assert _cats(_m("a();"), target, exceptions=[_exc()]) == []
    base = _m("// phpcs:ignore Generic.X.Y\na();\nb();")
    moved = _m("a();\n// phpcs:ignore Generic.X.Y\nb();")
    assert _cats(base, moved) == ["php_suppression_rebound"]
    assert _cats(base, moved, exceptions=[_exc()]) == []
    win = _m("// phpcs:disable Generic.X.Y\na();\n// phpcs:enable")
    assert _cats(_m("a();"), win) == ["php_suppression_range_expanded"]
    assert _cats(_m("a();"), win, exceptions=[_exc()]) == []


def test_exception_from_base_silences_only_matching_identity() -> None:
    target = _m("// phpcs:ignore Generic.X.Y\na();\n// phpcs:ignore Other.Z\nb();")
    base = _m("a();\nb();")
    assert _cats(base, target, exceptions=[_exc()]) == ["php_suppression_added"]
    for other in (_exc(symbol="V\\M\\X::other"), _exc(tool="phpstan"), _exc(codes=["Other.Z", "Generic.X.Y"]), _exc(path="app/code/V/M/Model/Y.php")):
        assert _cats(base, target, exceptions=[other]) == ["php_suppression_added", "php_suppression_added"]


def test_exception_does_not_silence_unknown_anchor_or_tests() -> None:
    target = _m("a();\n// @phpstan-ignore foo.bar")
    exc = _exc(tool="phpstan", codes=["foo.bar"])
    assert _cats(_m("a();"), target, exceptions=[exc]) == ["php_suppression_anchor_unknown"]


def test_deterministic_output_is_sorted() -> None:
    require_php()
    from agent_ratchet.php.compare import compare_php_entry

    target = _m("// phpcs:ignore B.B\na();\n// phpcs:ignore A.A\nb();")
    runs = [compare_php_entry(_m("a();\nb();").encode(), target.encode(), PATH, PATH, ()) for _ in range(3)]
    assert runs[0] == runs[1] == runs[2]
    assert [v.line for v in runs[0]] == sorted(v.line for v in runs[0])


def test_plugin_registered_once_with_spec_fact_shapes() -> None:
    require_php()
    import importlib

    from agent_ratchet.facts.plugin import get_plugin, registered_plugins
    from agent_ratchet.php import extract

    importlib.reload(extract)  # a second import must not raise on double registration
    assert registered_plugins().count("php") == 1
    src = _m("// phpcs:ignore A.B\na();\n// phpcs:disable\nb();\n// phpcs:enable\nc(;")
    facts = get_plugin("php").extract(src.encode(), PATH, {"blob_oid": "abc"})
    kinds = sorted({f.kind for f in facts})
    assert kinds == ["php.parse_gap", "php.suppression.point", "php.suppression.window"]
    point = next(f for f in facts if f.kind == "php.suppression.point")
    assert dict(point.identity) == {"path": PATH, "symbol": "V\\M\\X::run", "tool": "phpcs", "codes": ("A.B",)}
    assert set(point.payload) == {"anchor_ast_kind", "anchor_norm_hash", "decl_norm_hash"} and point.origin.blob_oid == "abc"
    assert all(f.completeness == "incomplete" for f in facts if f.kind != "php.parse_gap")  # symbol has a gap
    assert get_plugin("php").extract(src.encode(), PATH, {}) == get_plugin("php").extract(src.encode(), PATH, {})


def test_phtml_gets_no_test_rules() -> None:
    src = _t(_FULL)
    path = "app/design/frontend/V/M/templates/x.phtml"
    assert _cats(src, src.replace("$this->assertSame(1, 1);", ""), base_path=path, target_path=path) == []


# --- fix round 1: comment-only edits inside a symbol that already has a parse gap ---------------

_GAP_METHOD = "$a = 1;\n%sreturn foo(;"


def test_directive_added_inside_preexisting_gap_symbol_is_degraded() -> None:  # probes A, B
    base = _m(_GAP_METHOD % "")
    for directive in ("// @phpstan-ignore foo.bar\n", "// phpcs:disable\n"):
        assert _cats(base, _m(_GAP_METHOD % directive)) == ["php_parse_degraded"]


def test_directive_in_clean_method_of_class_with_class_level_gap_is_not_hidden() -> None:  # probe C
    cls = "<?php\nnamespace V\\M;\nclass X {\n    public $p = ;\n    public function ok() {\n%s        a();\n    }\n}\n"
    assert _cats(cls % "", cls % "        // phpcs:ignore\n") == ["php_parse_degraded"]
    assert _cats(cls % "", cls % "") == []


def test_suppression_in_clean_method_beside_unchanged_gap_method_is_added() -> None:
    src = "<?php\nnamespace V\\M;\nclass X {\n    public function a() {\n        return foo(;\n    }\n    public function ok() {\n%s        b();\n    }\n}\n"
    assert _cats(src % "", src % "        // phpcs:ignore A.B\n") == ["php_suppression_added"]


def test_test_weakened_beside_unchanged_gap_is_still_flagged() -> None:  # probe D: the docblock sits outside the method
    gap = _FULL + "\nreturn foo(;"
    assert _cats(_t(gap, doc=_DOC), _t(gap), base_path=TEST_PATH, target_path=TEST_PATH) == ["php_test_weakened"]


def test_test_annotation_dropped_in_class_with_class_level_gap_is_not_hidden() -> None:  # probe E
    cls = "<?php\nnamespace V\\M\\Test;\nuse PHPUnit\\Framework\\TestCase;\nclass XTest extends TestCase {\n    public $p = ;\n%s    public function itWorks() { $this->assertTrue(1); }\n}\n"
    assert _cats(cls % "    /** @test */\n", cls % "", base_path=TEST_PATH, target_path=TEST_PATH) == ["php_parse_degraded"]


# --- task 10a: symbol pairing for renames (spec R6 "Symbol pairing", R9 rows 15-16) -------------

_OLD_PATH = "app/code/Acme/Shop/Model/Cart.php"
_NEW_PATH = "app/code/Acme/Shop/Checkout/Model/Cart.php"


def _cart(body: str, ns: str = "Acme\\Shop\\Model", name: str = "run", extra: str = "") -> str:
    return f"<?php\nnamespace {ns};\nclass Cart {{\n    public function {name}() {{\n{body}\n    }}\n{extra}}}\n"


_IGNORED = "// phpcs:ignore Generic.Sample.Rule\na();\nb();"


def _moved(base: str, target: str) -> list[str]:
    return _cats(base, target, base_path=_OLD_PATH, target_path=_NEW_PATH, renamed=True)


def test_rename_with_namespace_change_passes() -> None:
    base = _cart(_IGNORED + "\n// @phpstan-ignore foo.bar\nc();")
    assert _moved(base, base.replace("Acme\\Shop\\Model", "Acme\\Shop\\Checkout\\Model")) == []


def test_rename_namespace_change_plus_new_ignore_is_added() -> None:
    base = _cart(_IGNORED)
    target = _cart(_IGNORED + "\n// phpcs:ignore Generic.Sample.Rule\nc();", ns="Acme\\Shop\\Checkout\\Model")
    assert _moved(base, target) == ["php_suppression_added"]


def test_window_symbol_survives_namespace_rename() -> None:
    body = "// phpcs:disable Generic.Sample.Rule\na();\n// phpcs:enable Generic.Sample.Rule\nz();"
    assert _moved(_cart(body), _cart(body, ns="Acme\\Shop\\Checkout\\Model")) == []


def test_method_rename_keeps_suppression() -> None:
    assert _cats(_cart(_IGNORED), _cart(_IGNORED, name="execute"), base_path=_OLD_PATH, target_path=_OLD_PATH) == []


def test_move_to_identical_statement_in_other_existing_method_is_added() -> None:
    other = "    public function other() {\n%s    }\n"
    base = _cart(_IGNORED, extra=other % "a();\n")
    target = _cart("a();\nb();", extra=other % "// phpcs:ignore Generic.Sample.Rule\na();\n")
    assert _cats(base, target, base_path=_OLD_PATH, target_path=_OLD_PATH) == ["php_suppression_added"]


def test_non_rename_pair_keeps_full_symbol() -> None:
    # Namespace edited in place and the ignored line edited: without R status the symbols differ, so the directive is a
    # new identity (added); the same edit under a rename strips the namespace and is a re-pointed identity (rebound).
    # A namespace-only in-place edit passes through the renamed-declaration clause (origin gone, destination new), not
    # the strip.
    base = _cart(_IGNORED)
    target = _cart("// phpcs:ignore Generic.Sample.Rule\na(1);\nb();", ns="Acme\\Shop\\Checkout\\Model")
    assert _cats(base, target, base_path=_OLD_PATH, target_path=_OLD_PATH) == ["php_suppression_added"]
    assert _moved(base, target) == ["php_suppression_rebound"]


# --- task 10a fix round 1: new destination required, unique strip, keyed parse gaps -------------

_FUNCS = "<?php\nnamespace Acme\\Shop\\Model;\n%s"
_FN = "function %s() {\n%s    f();\n}\n"
_IG = "    // phpcs:ignore Generic.Sample.Rule\n"


def test_rename_origin_and_move_directive_to_existing_method_is_added() -> None:
    base = _FUNCS % (_FN % ("a", _IG) + _FN % ("b", ""))
    target = _FUNCS % (_FN % ("a2", "") + _FN % ("b", _IG))
    assert _cats(base, target, base_path=_OLD_PATH, target_path=_OLD_PATH) == ["php_suppression_added"]


def test_delete_origin_and_move_directive_to_existing_method_is_added() -> None:
    base = _FUNCS % (_FN % ("a", _IG) + _FN % ("b", ""))
    target = _FUNCS % (_FN % ("b", _IG))
    assert _cats(base, target, base_path=_OLD_PATH, target_path=_OLD_PATH) == ["php_suppression_added"]


def _braced(a_body: str, b_body: str, prefix: str = "Acme\\Shop") -> str:
    cls = "namespace %s\\%s {\nclass Cart {\n    public function run() {\n%s        a();\n    }\n}\n}\n"
    return "<?php\n" + cls % (prefix, "A", a_body) + cls % (prefix, "B", b_body)


def test_braced_namespaces_same_class_name_keep_full_symbol_under_rename() -> None:
    ig = "        // phpcs:ignore Generic.Sample.Rule\n"
    assert _moved(_braced(ig, ""), _braced("", ig)) == ["php_suppression_added"]
    assert _moved(_braced(ig, ""), _braced(ig, "")) == []
    other = "    public function x() {\n        // phpcs:ignore Generic.Sample.Rule\n        a();\n    }\n"
    only_a = _braced("", "").replace("class Cart {\n", "class Cart {\n" + other, 1)
    assert _moved(_braced("", ""), only_a) == ["php_suppression_added"]


def test_unchanged_gap_in_renamed_namespace_file_passes() -> None:
    body = "$a = 1;\nreturn foo(;"
    base = _cart(body)
    target = _cart(body, ns="Acme\\Shop\\Checkout\\Model")
    assert _moved(base, target) == []
    assert _cats(base, target, base_path=_OLD_PATH, target_path=_NEW_PATH) == ["php_parse_degraded"]


# --- 4.1.3: one analysis per blob in a transition (audit D8) -----------------------------------------


def test_transition_parses_each_blob_once(monkeypatch) -> None:
    require_php()
    from agent_ratchet.php import extract, scan

    blobs = {f"BASE:{PATH}": _m("a();").encode(), f":{PATH}": _m("a();\nb();").encode()}
    monkeypatch.setattr(scan, "git_cat_bytes", lambda spec, cwd=None: blobs[spec])
    parsed: list[bytes] = []
    real = extract.parse_php
    monkeypatch.setattr(extract, "parse_php", lambda blob: parsed.append(blob) or real(blob))
    cfg = {"languages": ["php"], "frameworks": [], "php_paths": ["app/code/"]}
    assert scan.php_transition_violations([("M", PATH, PATH)], "BASE", "", cfg, cfg) == []
    assert sorted(parsed) == sorted(blobs.values())
