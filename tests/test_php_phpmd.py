"""PHPMD `@SuppressWarnings` docblock annotations as `phpmd` point facts (spec R4 "Declaration, PHPMD")."""

from __future__ import annotations

import pytest
from php_support import require_php


def _phpmd(src: str):
    require_php()
    from agent_ratchet.php.directives import collect
    from agent_ratchet.php.parser import parse_php

    pts, _, _ = collect(parse_php(src.encode()))
    return [p for p in pts if p.tool == "phpmd"]


def _method(doc: str, signature: str = "public function m(int $a): int", body: str = "return $a;") -> str:
    return f"<?php\nnamespace Acme\\Shop;\nclass Cart {{\n    {doc}\n    {signature}\n    {{\n        {body}\n    }}\n}}\n"


def test_phpmd_single_rule_fact():
    (p,) = _phpmd(_method("/** @SuppressWarnings(PHPMD.UnusedLocalVariable) */"))
    assert (p.tool, p.codes, p.anchor_kind, p.symbol) == (
        "phpmd",
        ("PHPMD.UnusedLocalVariable",),
        "method_declaration",
        "Acme\\Shop\\Cart::m",
    )
    assert p.anchor_hash and p.line == 4


def test_phpmd_all_is_empty_codes():
    for value in ("PHPMD", "PMD", '"PHPMD"'):
        (p,) = _phpmd(_method(f"/** @SuppressWarnings({value}) */"))
        assert p.codes == ()


def test_phpmd_quoted_value_trimmed():
    (p,) = _phpmd(_method('/** @SuppressWarnings("unused") */'))
    assert p.codes == ("unused",)
    (q,) = _phpmd(_method('/** @SuppressWarnings( "PHPMD.CamelCaseVariableName" ) */'))
    assert q.codes == ("PHPMD.CamelCaseVariableName",)


def test_phpmd_name_casing():
    (p,) = _phpmd(_method("/** @suppressWarnings(PHPMD.X) */"))
    assert p.codes == ("PHPMD.X",)
    assert _phpmd(_method("/** @SUPPRESSWARNINGS(PHPMD) */")) == []
    assert _phpmd(_method("/** @Suppresswarnings(PHPMD) */")) == []


def test_phpmd_multiple_in_one_docblock():
    doc = "/**\n     * Totals.\n     *\n     * @SuppressWarnings(PHPMD.ExcessiveMethodLength)\n     * @SuppressWarnings(PHPMD.NPathComplexity)\n     */"
    pts = _phpmd(_method(doc))
    assert sorted((p.codes, p.line) for p in pts) == [
        (("PHPMD.ExcessiveMethodLength",), 7),
        (("PHPMD.NPathComplexity",), 8),
    ]
    assert pts[0].anchor_hash is not None and pts[0].anchor_hash == pts[1].anchor_hash


def test_phpmd_anchor_ignores_body_and_formatting():
    doc = "/** @SuppressWarnings(PHPMD.UnusedLocalVariable) */"
    (base,) = _phpmd(_method(doc))
    (body_edit,) = _phpmd(_method(doc, body="$unused = 1;\n        return $a + 1;"))
    (reformatted,) = _phpmd(_method(doc, signature="public  function m(\n        int $a\n    ): int"))
    assert base.anchor_hash == body_edit.anchor_hash == reformatted.anchor_hash


def test_phpmd_anchor_ignores_parameters():
    doc = "/** @SuppressWarnings(PHPMD.ExcessiveParameterList) */"
    (base,) = _phpmd(_method(doc))
    (param,) = _phpmd(_method(doc, signature="public function m(int $a, int $b): int"))
    assert base.anchor_hash == param.anchor_hash


def test_phpmd_anchor_ignores_modifiers_and_return_type():
    doc = "/** @SuppressWarnings(PHPMD.UnusedLocalVariable) */"
    (base,) = _phpmd(_method(doc))
    (visibility,) = _phpmd(_method(doc, signature="protected function m(int $a): int"))
    (retype,) = _phpmd(_method(doc, signature="public function m(int $a): ?int"))
    (untyped,) = _phpmd(_method(doc, signature="public function m(int $a)"))
    assert base.anchor_hash == visibility.anchor_hash == retype.anchor_hash == untyped.anchor_hash


def test_phpmd_anchor_kind_and_name():
    doc = "/** @SuppressWarnings(PHPMD) */"
    (base,) = _phpmd(_method(doc))
    (renamed,) = _phpmd(_method(doc, signature="public function n(int $a): int"))
    assert base.anchor_hash != renamed.anchor_hash
    as_class = f"<?php\nnamespace Acme\\Shop;\n{doc}\nclass Cart {{}}\n"
    as_function = f"<?php\nnamespace Acme\\Shop;\n{doc}\nfunction Cart() {{}}\n"
    (c,) = _phpmd(as_class)
    (f,) = _phpmd(as_function)
    assert c.anchor_hash != f.anchor_hash


def test_phpmd_on_class_and_function():
    src = (
        "<?php\nnamespace Acme\\Shop;\n"
        "/** @SuppressWarnings(PHPMD.CouplingBetweenObjects) */\nfinal class Cart {}\n"
        "/** @SuppressWarnings(PHPMD.ShortVariable) */\ninterface Priced {}\n"
        "/** @SuppressWarnings(PHPMD.TooManyMethods) */\ntrait Totals {}\n"
        "/** @SuppressWarnings(PHPMD.LongVariable) */\nenum Status {}\n"
        "/** @SuppressWarnings(PHPMD) */\nfunction helper() {}\n"
    )
    got = sorted((p.symbol, p.anchor_kind, p.codes) for p in _phpmd(src))
    assert got == [
        ("Acme\\Shop\\Cart", "class_declaration", ("PHPMD.CouplingBetweenObjects",)),
        ("Acme\\Shop\\Priced", "interface_declaration", ("PHPMD.ShortVariable",)),
        ("Acme\\Shop\\Status", "enum_declaration", ("PHPMD.LongVariable",)),
        ("Acme\\Shop\\Totals", "trait_declaration", ("PHPMD.TooManyMethods",)),
        ("Acme\\Shop\\helper", "function_definition", ()),
    ]


def test_phpmd_orphan_docblock_anchor_null():
    on_property = "<?php\nnamespace Acme\\Shop;\nclass Cart {\n    /** @SuppressWarnings(PHPMD) */\n    private int $p = 1;\n}\n"
    at_end = "<?php\nnamespace Acme\\Shop;\nclass Cart {\n    /** @SuppressWarnings(PHPMD) */\n}\n"
    in_body = _method("/** doc */", body="/** @SuppressWarnings(PHPMD) */\n        return $a;")
    for src in (on_property, at_end, in_body):
        (p,) = _phpmd(src)
        assert (p.anchor_kind, p.anchor_hash) == (None, None), src


def test_phpmd_in_line_comment_ignored():
    for doc in ("// @SuppressWarnings(PHPMD)", "# @SuppressWarnings(PHPMD)", "/* @SuppressWarnings(PHPMD) */"):
        assert _phpmd(_method(doc)) == [], doc


def test_phpmd_docblock_keeps_other_directives():
    pts_src = _method("/**\n     * @psalm-suppress MixedReturn\n     * @SuppressWarnings(PHPMD.X)\n     */")
    require_php()
    from agent_ratchet.php.directives import collect
    from agent_ratchet.php.parser import parse_php

    pts, _, _ = collect(parse_php(pts_src.encode()))
    assert sorted((p.tool, p.codes) for p in pts) == [("phpmd", ("PHPMD.X",)), ("psalm", ("MixedReturn",))]


# --- attachment follows PDepend (spec R4 "Precedes") ------------------------------------------

SW = "/** @SuppressWarnings(PHPMD) */"


def _cats(base: str, target: str) -> list[str]:
    require_php()
    from agent_ratchet.php.compare import compare_php_entry

    path = "app/code/Acme/Shop/Model/Cart.php"
    return [v.category for v in compare_php_entry(base.encode(), target.encode(), path, path, ())]


def _cart(members: str, head: str = "") -> str:
    return f"<?php\nnamespace Acme\\Shop\\Model;\n\n{head}class Cart\n{{\n{members}}}\n"


def _fn(name: str, body: str = "return 1;") -> str:
    return f"    public function {name}(): int\n    {{\n        {body}\n    }}\n"


@pytest.mark.parametrize("between", ["// note", "# note", "/* note */", "/**/", "", "#[\\Acme\\Shop\\Marker]"])
def test_phpmd_attaches_through_non_doc_comments_and_attributes(between):
    (p,) = _phpmd(_cart(f"    {SW}\n    {between}\n" + _fn("a")))
    assert (p.symbol, p.anchor_kind) == ("Acme\\Shop\\Model\\Cart::a", "method_declaration")
    assert p.anchor_hash is not None


def test_phpmd_attaches_through_trait_use():
    (p,) = _phpmd(_cart(f"    {SW}\n    use Totals;\n    use Prices, Rates;\n\n" + _fn("a")))
    assert (p.symbol, p.anchor_kind) == ("Acme\\Shop\\Model\\Cart::a", "method_declaration")


def test_phpmd_intervening_docblock_orphans_the_earlier_one():
    (p,) = _phpmd(_cart(f"    {SW}\n    /** Plain. */\n" + _fn("a")))
    assert (p.anchor_kind, p.anchor_hash) == (None, None)
    (q,) = _phpmd(_cart(f"    /** Plain. */\n    {SW}\n" + _fn("a")))
    assert q.anchor_kind == "method_declaration"


def test_phpmd_method_added_under_trait_use_docblock_is_flagged():  # review probe E1
    base = _cart(f"    {SW}\n    use Totals;\n")
    assert "php_suppression_added" in _cats(base, _cart(f"    {SW}\n    use Totals;\n\n" + _fn("a")))


def test_phpmd_method_swapped_under_trait_use_docblock_is_flagged():  # review probe E1c
    base = _cart(f"    {SW}\n    use Totals;\n\n" + _fn("a"))
    target = _cart(f"    {SW}\n    use Totals;\n\n" + _fn("b") + "\n" + _fn("a"))
    assert "php_suppression_added" in _cats(base, target)
    assert _cats(base, _cart(f"    {SW}\n    use Totals;\n\n" + _fn("a", "return 2;"))) == []


def test_phpmd_unshadowed_docblock_is_flagged():  # review probes E2, E2b
    base = _cart(f"    {SW}\n    /** Plain. */\n" + _fn("a"))
    assert "php_suppression_added" in _cats(base, _cart(f"    {SW}\n" + _fn("a")))
    base_cls = _cart(_fn("a"), head=f"{SW}\n/** Plain. */\n")
    assert "php_suppression_added" in _cats(base_cls, _cart(_fn("a"), head=f"{SW}\n"))


# --- cross-symbol pairing needs an equal declaration header (task 10f fix round 1) ------------

_SW = "/** @SuppressWarnings(PHPMD.UnusedLocalVariable) */"


def _cats(base: str, target: str) -> list[str]:
    require_php()
    from agent_ratchet.php.compare import compare_php_entry

    path = "app/code/Acme/Shop/Model/Cart.php"
    found = compare_php_entry(base.encode(), target.encode(), path, path, (), renamed=False)
    return [v.category for v in found]


def _cls(name: str, sig: str = "public function m(int $a): int", body: str = "return $a;", doc: str = _SW) -> str:
    return f"class {name} {{\n    {doc}\n    {sig}\n    {{\n        {body}\n    }}\n}}\n"


_HEAD = "<?php\nnamespace Acme\\Shop;\n"


def test_phpmd_deleted_class_recreated_with_other_header_is_added():
    base = _HEAD + _cls("A")
    target = _HEAD + _cls("B", sig="protected function m(string $s, int $n): string", body="return $s;")
    assert _cats(base, target) == ["php_suppression_added"]


def test_phpmd_deleted_method_recreated_elsewhere_with_other_header_is_added():
    base = _HEAD + _cls("A") + "class Keep {}\n"
    target = _HEAD + "class A {}\n" + _cls("B", sig="protected function m(string $s): string", body="return $s;")
    assert _cats(base, target) == ["php_suppression_added"]


def test_phpmd_pure_class_rename_with_identical_header_pairs():
    assert _cats(_HEAD + _cls("A"), _HEAD + _cls("B", body="$x = 1;\n        return $a;")) == []


def test_phpmd_same_symbol_header_change_still_passes():
    assert _cats(_HEAD + _cls("A"), _HEAD + _cls("A", sig="protected function m(int $a, int $b): ?int")) == []
