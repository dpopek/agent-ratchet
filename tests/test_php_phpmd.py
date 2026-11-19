"""PHPMD `@SuppressWarnings` docblock annotations as `phpmd` point facts (spec R4 "Declaration, PHPMD")."""

from __future__ import annotations

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
    assert {p.anchor_hash for p in pts} != {None}


def test_phpmd_anchor_header_only():
    doc = "/** @SuppressWarnings(PHPMD.UnusedLocalVariable) */"
    (base,) = _phpmd(_method(doc))
    (body_edit,) = _phpmd(_method(doc, body="$unused = 1;\n        return $a + 1;"))
    (param,) = _phpmd(_method(doc, signature="public function m(int $a, int $b): int"))
    (reformatted,) = _phpmd(_method(doc, signature="public  function m(\n        int $a\n    ): int"))
    assert base.anchor_hash == body_edit.anchor_hash == reformatted.anchor_hash
    assert param.anchor_hash != base.anchor_hash


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
