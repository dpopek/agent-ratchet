from __future__ import annotations

import pytest
from php_support import require_php


def _collect(src: str | bytes):
    require_php()
    from agent_ratchet.php.directives import collect
    from agent_ratchet.php.parser import parse_php

    blob = src.encode() if isinstance(src, str) else src
    return collect(parse_php(blob))


def _wrap(body: str) -> str:
    return f"<?php\nnamespace A\\B;\nclass C {{\n    public function m() {{\n{body}\n    }}\n}}\n"


def test_phpstan_ignore_own_line_anchors_next_statement():
    pts, _, _ = _collect(_wrap("        // @phpstan-ignore foo.bar, argument.type (why)\n        run();"))
    (p,) = pts
    assert (p.tool, p.codes, p.anchor_kind, p.symbol) == (
        "phpstan",
        ("argument.type", "foo.bar"),
        "expression_statement",
        "A\\B\\C::m",
    )
    assert p.anchor_hash and p.line == 5


def test_phpstan_ignore_line_trailing_anchors_same_statement():
    pts, _, _ = _collect(_wrap("        $a = 1;\n        run($a); // @phpstan-ignore-line"))
    (p,) = pts
    assert (p.tool, p.codes, p.anchor_kind) == ("phpstan", (), "expression_statement")
    other, _, _ = _collect(_wrap("        $a = 1;\n        run($a); // plain"))
    assert other == []
    again, _, _ = _collect(_wrap("        other($a); // @phpstan-ignore-line"))
    assert again[0].anchor_hash != p.anchor_hash


def test_phpstan_ignore_next_line():
    pts, _, _ = _collect(_wrap("        /* @phpstan-ignore-next-line */\n        run();"))
    assert pts[0].codes == () and pts[0].anchor_kind == "expression_statement"


def test_phpcs_ignore_codes_and_reason():
    pts, _, _ = _collect(_wrap("        // phpcs:ignore B.Y, A.X, A.X -- why\n        run();"))
    assert pts[0].tool == "phpcs" and pts[0].codes == ("A.X", "B.Y")


def test_phpcs_ignore_without_codes_is_all():
    pts, _, _ = _collect(_wrap("        // phpcs:ignore\n        run();"))
    assert pts[0].codes == () and pts[0].anchor_kind == "expression_statement"


def test_psalm_suppress_anchors_declaration():
    src = "<?php\nnamespace A\\B;\nclass C {\n    /** @psalm-suppress Foo, Bar */\n    public function m() {}\n}\n"
    pts, _, _ = _collect(src)
    (p,) = pts
    assert (p.tool, p.codes, p.anchor_kind, p.symbol) == (
        "psalm",
        ("Bar", "Foo"),
        "method_declaration",
        "A\\B\\C::m",
    )


def test_legacy_ignore_line_start_end_file():
    src = (
        "<?php\n// @codingStandardsIgnoreFile\n"
        "// @codingStandardsIgnoreLine\n$a = 1;\n"
        "// @codingStandardsIgnoreStart\n$b = 2;\n$c = 3;\n// @codingStandardsIgnoreEnd\n$d = 4;\n"
    )
    pts, wins, files = _collect(src)
    assert [(f.tool, f.codes) for f in files] == [("phpcs", ())]
    assert pts[0].tool == "phpcs" and pts[0].anchor_kind == "expression_statement"
    (w,) = wins
    assert w.closed is False and len(w.statements) == 3  # PHPCS 4 honours no legacy End, so the window runs to EOF


def test_phpcs_keyword_prefix_semantics():
    _, wins, _ = _collect("<?php\n// phpcs:disabled\n$a = 1;\n// phpcs:enabled\n$b = 2;\n")
    (w,) = wins
    assert (w.codes, w.closed, len(w.statements)) == ((), True, 1)
    (p,), _, _ = _collect(_wrap("        // phpcs:ignored\n        run();"))
    assert (p.tool, p.codes, p.anchor_kind) == ("phpcs", (), "expression_statement")
    _, wins, _ = _collect("<?php\n// phpcs:disablefoo\n$a = 1;\n")
    assert [(w.codes, w.closed) for w in wins] == [(("oo",), False)]
    pts, wins, files = _collect("<?php\n// phpcs:ignorefiles\n$a = 1;\n")
    assert [(f.tool, f.codes) for f in files] == [("phpcs", ())] and pts == wins == []
    for directive in ("phpcs:set X.Y.Z prop 1", "phpcs:foo"):
        (p,), _, _ = _collect(_wrap(f"        // {directive}\n        run();"))
        assert p.tool == "phpcs-unknown" and p.anchor_kind is None and p.anchor_hash is None, directive


def test_window_closed_and_statements():
    src = "<?php\n$a = 1;\n// phpcs:disable X.Y\n$b = 2;\nfoo();\n// phpcs:enable X.Y\n$c = 3;\n"
    _, wins, _ = _collect(src)
    (w,) = wins
    assert (w.closed, w.codes, w.symbol, w.line) == (True, ("X.Y",), "<file>", 3)
    assert len(w.statements) == 2 and list(w.statements) == sorted(w.statements)


@pytest.mark.parametrize(
    ("directive", "codes"),
    [
        ("phpcs:ignore A.B C.D", ("A.B C.D",)),
        ("phpcs:ignore (A.B)", ("(A.B)",)),
        ("phpcs:ignore A.B--x", ("A.B--x",)),
        ("phpcs:ignore A.B -- why, C.D", ("A.B",)),
        ("phpcs:ignore B.Y , A.X,,A.X", ("A.X", "B.Y")),
        ("phpcs:ignore -- why", ()),
        ("phpcs:ignore,A.B", ("A.B",)),
    ],
)
def test_phpcs_codes_follow_phpcs_comma_list(directive, codes):
    (p,), _, _ = _collect(_wrap(f"        // {directive}\n        run();"))
    assert (p.tool, p.codes) == ("phpcs", codes)


@pytest.mark.parametrize(
    ("enable", "closes"),
    [
        ("phpcs:enable A.B C.D", False),
        ("phpcs:enable (A.B)", False),
        ("phpcs:enable A.B--x", False),
        ("phpcs:enable A.B -- done", True),
        ("phpcs:enable C.D, A.B", True),
    ],
)
def test_phpcs_enable_closes_only_on_phpcs_code_match(enable, closes):
    _, wins, _ = _collect(f"<?php\n// phpcs:disable A.B\n$a = 1;\n// {enable}\n$b = 2;\n")
    (w,) = wins
    assert (w.codes, w.closed, len(w.statements)) == (("A.B",), closes, 1 if closes else 2)


@pytest.mark.parametrize(
    ("enable", "closes"),
    [
        ("// note phpcs:enable", False),  # PHPCS honours a keyword only at the start of the line's text (G6)
        ("/* note phpcs:enable A.B */", False),
        ("// phpcs:ignore X.Y -- phpcs:enable", False),
        ("// phpcs:enable", True),
        ("# @phpcs:enable A.B", True),
        ("/* phpcs:enable */", True),
        ("/**\n * note\n * phpcs:enable\n */", True),
        ("/*\n   phpcs:enable A.B */", True),
        ("// note @codingStandardsIgnoreEnd", False),  # PHPCS 4 ignores legacy annotations: End closes nothing
        # PHPCS trims only " \t/*#" before a keyword: NBSP or form feed makes it mid-text (G2/G6, probed 4.0.4)
        ("//  phpcs:enable", False),
        ("//\u000cphpcs:enable", False),
        ("/*\n  * phpcs:enable */", False),
        ("// phpcs:enable A.B ", False),  # PHP trim() keeps NBSP, so the code is `A.B<NBSP>`
        ("// phpcs:enable A.B \t", True),
    ],
)
def test_phpcs_enable_only_at_start_of_comment_line(enable, closes):
    _, wins, _ = _collect(f"<?php\n// phpcs:disable A.B\n$a = 1;\n{enable}\n$b = 2;\n")
    (w,) = wins
    assert (w.closed, len(w.statements)) == (closes, 1 if closes else 2)


def test_mid_text_phpcs_keywords_other_than_enable_stay_recorded():
    pts, wins, files = _collect(
        "<?php\n// note phpcs:ignore A.B\n$a = 1;\n// note phpcs:disable C.D\n$b = 1;\n// note phpcs:ignoreFile\n"
        "// note phpcs:set X.Y.Z p 1\n"
    )
    assert sorted(p.tool for p in pts) == ["phpcs", "phpcs-unknown"]
    assert [w.codes for w in wins] == [("C.D",)] and [f.tool for f in files] == ["phpcs"]


@pytest.mark.parametrize("space", [" ", "\u000c"])
def test_unicode_space_before_other_phpcs_keywords_keeps_them_recorded(space):
    pts, wins, _ = _collect(f"<?php\n//{space}phpcs:ignore A.B\n$a = 1;\n//{space}phpcs:disable C.D\n$b = 1;\n")
    assert [(p.tool, p.codes) for p in pts] == [("phpcs", ("A.B",))]
    assert [(w.codes, w.closed) for w in wins] == [(("C.D",), False)]


def test_unicode_space_does_not_hide_other_tools():
    pts, _, _ = _collect(
        _wrap("        // @phpstan-ignore x.y \n        a();\n        /** @psalm-suppress Foo */\n        b();")
    )
    assert sorted((p.tool, p.codes) for p in pts) == [("phpstan", ("x.y",)), ("psalm", ("Foo",))]


def test_window_unclosed_runs_to_eof():
    src = "<?php\n// phpcs:disable\n$b = 2;\n$c = 3;\n"
    _, wins, _ = _collect(src)
    (w,) = wins
    assert w.closed is False and len(w.statements) == 2


def test_enable_with_codes_closes_only_matching():
    src = "<?php\n// phpcs:disable A\n// phpcs:disable B\n$x = 1;\n// phpcs:enable A\n$y = 2;\n"
    _, wins, _ = _collect(src)
    by_codes = {w.codes: w for w in wins}
    assert by_codes[("A",)].closed is True and len(by_codes[("A",)].statements) == 1
    assert by_codes[("B",)].closed is False and len(by_codes[("B",)].statements) == 2


def test_anchor_none_at_end_of_block():
    pts, _, _ = _collect(_wrap("        run();\n        // phpcs:ignore"))
    (p,) = pts
    assert p.anchor_kind is None and p.anchor_hash is None


def test_symbol_path_method_class_function_file():
    require_php()
    from agent_ratchet.php.directives import symbol_path
    from agent_ratchet.php.parser import parse_php

    src = b"<?php\nnamespace A\\B;\nclass C { public function m() {} }\nfunction f() {}\n$t = 1;\n"
    root = parse_php(src).tree.root_node
    found = {}
    stack = [root]
    while stack:
        n = stack.pop()
        found.setdefault(n.type, n)
        stack.extend(n.children)
    assert symbol_path(found["method_declaration"], src, "A\\B") == "A\\B\\C::m"
    assert symbol_path(found["class_declaration"], src, "A\\B") == "A\\B\\C"
    assert symbol_path(found["function_definition"], src, "A\\B") == "A\\B\\f"
    assert symbol_path(found["expression_statement"], src, "A\\B") == "<file>"


def test_non_utf8_identifier_is_degraded_not_crash():
    require_php()
    from agent_ratchet.php.directives import PhpDecodeError

    assert issubclass(PhpDecodeError, ValueError)
    src = b"<?php\nnamespace A\\B;\nclass C\xff {\n    public function m() {\n        // phpcs:ignore\n        run();\n    }\n}\n"
    with pytest.raises(PhpDecodeError):
        _collect(src)


def test_directives_are_case_insensitive():
    pts, _, _ = _collect(_wrap("        // PHPCS:ignore A.X\n        run();"))
    assert [(p.tool, p.codes) for p in pts] == [("phpcs", ("A.X",))]
    _, wins, _ = _collect("<?php\n// PhpCs:Disable\n$a = 1;\n// PhpCs:Enable\n$b = 2;\n")
    assert len(wins) == 1 and wins[0].closed and len(wins[0].statements) == 1
    pts, _, files = _collect("<?php\n// PHPCS:IGNOREFILE\n// @CodingStandardsIgnoreLine\n$a = 1;\n")
    assert [f.tool for f in files] == ["phpcs"] and pts[0].anchor_kind == "expression_statement"
    pts, _, _ = _collect(_wrap("        run(); // @PHPStan-Ignore-Line"))
    assert [(p.tool, p.codes) for p in pts] == [("phpstan", ())]
    pts, _, _ = _collect(_wrap("        // PHPCS:Bogus\n        run();"))
    assert pts[0].tool == "phpcs-unknown"


def test_directive_inside_reason_is_still_recorded():
    base, _, _ = _collect(_wrap("        run(); // phpcs:ignore X.Y -- because"))
    tgt, _, _ = _collect(_wrap("        run(); // phpcs:ignore X.Y -- @phpstan-ignore-line"))
    assert [p.tool for p in base] == ["phpcs"]
    assert sorted((p.tool, p.codes) for p in tgt) == [("phpcs", ("X.Y",)), ("phpstan", ())]


def test_multiple_directives_on_one_line_split_codes():
    pts, _, _ = _collect(
        _wrap("        /** @psalm-suppress A @phpstan-ignore x.y */\n        run();")
    )
    assert sorted((p.tool, p.codes) for p in pts) == [("phpstan", ("x.y",)), ("psalm", ("A",))]


def test_trailing_next_line_anchors_next_statement():
    a, _, _ = _collect(_wrap("        a(); // @phpstan-ignore-next-line\n        b();"))
    b, _, _ = _collect(_wrap("        a(); // @phpstan-ignore-next-line\n        bad();"))
    own, _, _ = _collect(_wrap("        a();\n        // @phpstan-ignore-next-line\n        b();"))
    assert a[0].anchor_hash != b[0].anchor_hash
    assert a[0].anchor_hash == own[0].anchor_hash


_SIG = "<?php\nnamespace A\\B;\nclass C {\n    // phpcs:ignore X.Y.Z\n    public function m(\n        int $a\n    ): int {\n        return {body};\n    }\n}\n"


def _sig(body: str = "1", first: str = "public function m(") -> str:
    return _SIG.replace("{body}", body).replace("public function m(", first)


def test_phpcs_ignore_fingerprint_ignores_body_edit():
    import hashlib

    from agent_ratchet.php.parser import NORM_DOMAIN

    (base,), _, _ = _collect(_sig("1"))
    (edited,), _, _ = _collect(_sig("$a + 2"))
    assert base.anchor_kind == edited.anchor_kind == "method_declaration"
    assert base.anchor_hash == edited.anchor_hash
    header = b"public function m ( int $ a ) : int"
    assert base.anchor_hash == hashlib.sha256(NORM_DOMAIN + header).hexdigest()


def test_phpcs_ignore_fingerprint_changes_when_ignored_line_edited():
    (base,), _, _ = _collect(_sig())
    (edited,), _, _ = _collect(_sig(first="protected function m("))
    assert base.anchor_kind == edited.anchor_kind == "method_declaration"
    assert base.anchor_hash != edited.anchor_hash


def test_trailing_ignore_fingerprints_own_line():
    def one(head: str, body: str) -> object:
        (p,), _, _ = _collect(_wrap(f"        {head} {{ // phpcs:ignore\n            {body}\n        }}"))
        return p

    base = one("if ($x)", "a();")
    assert base.anchor_kind == "if_statement"
    assert one("if ($x)", "b(1);").anchor_hash == base.anchor_hash
    assert one("if ($y)", "a();").anchor_hash != base.anchor_hash


def test_own_line_ignore_targets_literal_next_row():
    from agent_ratchet.php.parser import EMPTY_LINE

    plain, _, _ = _collect(_wrap("        // phpcs:ignore\n        run();"))
    blank, _, _ = _collect(_wrap("        // phpcs:ignore\n\n        run();"))
    note, _, _ = _collect(_wrap("        // phpcs:ignore\n        // note\n        run();"))
    assert blank[0].anchor_hash == note[0].anchor_hash == EMPTY_LINE
    assert plain[0].anchor_hash != blank[0].anchor_hash  # deleting the blank row is a rebound


@pytest.mark.parametrize("directive", ["phpcs:ignore", "@phpstan-ignore function.notFound"])
@pytest.mark.parametrize("opening", ["/* ", "/* note\n        "])
def test_block_comment_with_code_on_end_row_targets_that_row(directive, opening):
    def one(code: str, nxt: str) -> object:
        (p,), _, _ = _collect(_wrap(f"        {opening}{directive} */ {code}\n        {nxt}"))
        return p

    base = one("sizeof($a);", "next();")
    (trailing,), _, _ = _collect(_wrap(f"        sizeof($a); // {directive}\n        next();"))
    assert base.anchor_kind == "expression_statement"
    assert base.anchor_hash == trailing.anchor_hash  # fingerprint of the end row, not the next one
    assert one("sizeof($b);", "next();").anchor_hash != base.anchor_hash  # the ignored code edited: rebound
    assert one("sizeof($a);", "other(1);").anchor_hash == base.anchor_hash  # the next row is not covered


def test_only_comments_after_block_directive_keep_next_row():
    own, _, _ = _collect(_wrap("        // phpcs:ignore\n        run();"))
    only, _, _ = _collect(_wrap("        /* phpcs:ignore */ /* note */ // more\n        run();"))
    code, _, _ = _collect(_wrap("        /* phpcs:ignore */ /* note */ x();\n        run();"))
    (trailing,), _, _ = _collect(_wrap("        x(); // phpcs:ignore\n        run();"))
    assert only[0].anchor_hash == own[0].anchor_hash
    assert code[0].anchor_hash == trailing.anchor_hash


def _row_hashes(src: str) -> tuple[object, list[str]]:
    from agent_ratchet.php.parser import line_hash, parse_php

    (p,), _, _ = _collect(src)
    parsed = parse_php(src.encode())
    rows = src.count("\n") + 1
    return p, [line_hash(parsed.tree.root_node, parsed.source, r) for r in range(rows)]


_TAG_ROW = "<?php\n$a = [];\n{row}\n<?php sizeof($a);\n"  # directive on row 2, next row 3
_PHTML = "<div>\n{row}\n<?php sizeof($a); ?>\n"  # directive on row 1, next row 2


@pytest.mark.parametrize(
    ("template", "row", "target"),
    [
        # PHPCS skips the open and close tags when it looks for content on the directive's row (G4)
        (_TAG_ROW, "// phpcs:ignore ?>", 3),
        (_TAG_ROW, "/* phpcs:ignore */ ?>", 3),
        (_PHTML, "<?php // phpcs:ignore ?>", 2),
        (_PHTML, "<?php /* phpcs:ignore */ ?>", 2),
        (_TAG_ROW, "// @codingStandardsIgnoreLine ?>", 3),
        (_TAG_ROW, "$b = 1; /* phpcs:ignore */ ?>", 2),  # real code on the row keeps it there
        (_TAG_ROW, "/* phpcs:ignore */ $b = 1; ?>", 2),
        # PHPStan counts the tags as code: the directive's own row (anchor may be unresolved there)
        (_PHTML, "<?php // @phpstan-ignore x ?>", 1),
        (_TAG_ROW, "/* @phpstan-ignore x */ ?>", 2),
        (_TAG_ROW, "// @phpstan-ignore x ?>", 2),
        (_TAG_ROW, "// @phpstan-ignore-next-line ?>", 3),
        (_TAG_ROW, "/* @phpstan-ignore-next-line */ ?>", 3),
        (_PHTML, "<?php // @phpstan-ignore-next-line ?>", 2),
    ],
)
def test_php_tags_on_directive_row_follow_each_tool(template, row, target):
    p, rows = _row_hashes(template.format(row=row))
    if p.anchor_hash is None:
        assert p.tool == "phpstan" and target != len(rows) - 2, "only PHPStan's own tag row may stay unanchored"
    else:
        assert p.anchor_hash == rows[target]
    if target == len(rows) - 2:  # the next row is the one ignored: editing it must rebind
        edited, _ = _row_hashes(template.format(row=row).replace("sizeof($a)", "sizeof($b)"))
        assert edited.anchor_hash != p.anchor_hash


def test_next_line_block_comment_with_code_still_targets_next_row():
    own, _, _ = _collect(_wrap("        x();\n        // @phpstan-ignore-next-line\n        y();"))
    same, _, _ = _collect(_wrap("        /* @phpstan-ignore-next-line */ x();\n        y();"))
    edited, _, _ = _collect(_wrap("        /* @phpstan-ignore-next-line */ changed(2);\n        y();"))
    bad, _, _ = _collect(_wrap("        /* @phpstan-ignore-next-line */ x();\n        bad();"))
    assert same[0].anchor_hash == own[0].anchor_hash == edited[0].anchor_hash
    assert bad[0].anchor_hash != same[0].anchor_hash


def test_trailing_multiline_block_uses_directive_row():
    a, _, _ = _collect(_wrap("        foo(); /* note\n        @phpstan-ignore-line */ bar();"))
    b, _, _ = _collect(_wrap("        foo(); /* note\n        @phpstan-ignore-line */ baz();"))
    assert a[0].anchor_hash != b[0].anchor_hash


def test_fingerprint_counts_tokens_spanning_the_row():
    a, _, _ = _collect(_wrap('        foo("a\nb"); // phpcs:ignore X.Y'))
    b, _, _ = _collect(_wrap('        foo("z\nb"); // phpcs:ignore X.Y'))
    assert a[0].anchor_hash != b[0].anchor_hash


def _decl(directive: str, sig: str, body: str = "return 1;") -> object:
    src = f"<?php\nnamespace A\\B;\nclass C {{\n    // {directive}\n    {sig} {{\n        {body}\n    }}\n}}\n"
    (p,), _, _ = _collect(src)
    return p


def test_declaration_anchor_uses_header_hash():
    for directive in ("@phpstan-ignore Code.X", "@phpstan-ignore-next-line", "phpcs:ignore A.B.C"):
        base = _decl(directive, "public function m(\n        int $a\n    ): int")
        assert base.anchor_kind == "method_declaration"
        for sig in (
            "public function m(\n        int $a, int $b\n    ): int",
            "public function m(\n        int $a\n    )",
        ):
            assert _decl(directive, sig).anchor_hash != base.anchor_hash, (directive, sig)
    base = _decl("phpcs:ignore A.B.C", "public\n    function m()")
    assert _decl("phpcs:ignore A.B.C", "public\n    static function m()").anchor_hash != base.anchor_hash
    coded = _decl("phpcs:ignore A.B.C", "public function m()")
    assert _decl("phpcs:ignore A.B.C", "public function m()", "return 2;").anchor_hash == coded.anchor_hash


def test_declaration_anchor_keeps_node_hash_for_all_codes_and_metrics():
    for directive in ("phpcs:ignore", "phpcs:ignore Generic.Metrics.CyclomaticComplexity"):
        base = _decl(directive, "public function m()")
        assert _decl(directive, "public function m()", "return 2;").anchor_hash != base.anchor_hash
    src = "<?php\nnamespace A\\B;\n// phpcs:ignore\nclass C {\n    public function a() {}\n    public function b() {}\n}\n"
    (full,), _, _ = _collect(src)
    (deleted,), _, _ = _collect(src.replace("    public function b() {}\n", ""))
    assert full.anchor_kind == deleted.anchor_kind == "class_declaration"
    assert full.anchor_hash != deleted.anchor_hash


def test_phpstan_ignore_next_line_uses_fingerprint():
    def one(body: str) -> object:
        (p,), _, _ = _collect(_wrap(f"        // @phpstan-ignore-next-line\n        if ($x) {{\n            {body}\n        }}"))
        return p

    assert one("a();").anchor_kind == "if_statement"
    assert one("a();").anchor_hash == one("b(2);").anchor_hash
    for directive in ("@phpstan-ignore x.y", "@codingStandardsIgnoreLine"):
        a, _, _ = _collect(_wrap(f"        // {directive}\n        try {{\n            a();\n        }} catch (E $e) {{}}"))
        b, _, _ = _collect(_wrap(f"        // {directive}\n        try {{\n            b();\n        }} catch (E $e) {{}}"))
        assert a[0].anchor_hash == b[0].anchor_hash, directive


def test_psalm_suppress_keeps_node_hash():
    src = "<?php\nnamespace A\\B;\nclass C {\n    /** @psalm-suppress Foo */\n    public function m() {\n        return {body};\n    }\n}\n"
    (a,), _, _ = _collect(src.replace("{body}", "1"))
    (b,), _, _ = _collect(src.replace("{body}", "2"))
    assert a.anchor_kind == b.anchor_kind == "method_declaration"
    assert a.anchor_hash != b.anchor_hash


def test_fingerprint_crlf_and_reindent_stable():
    (base,), _, _ = _collect(_sig())
    (crlf,), _, _ = _collect(_sig().replace("\n", "\r\n"))
    (reindented,), _, _ = _collect(_sig(first="public   function   m (").replace("    ", "\t"))
    assert base.anchor_hash == crlf.anchor_hash == reindented.anchor_hash


def test_comment_before_directive_on_its_row_is_not_trailing():
    a, _, _ = _collect(_wrap("        /* a */ // phpcs:ignore X.Y\n        foo();"))
    b, _, _ = _collect(_wrap("        /* a */ // phpcs:ignore X.Y\n        bar();"))
    assert a[0].anchor_kind == "expression_statement"
    assert a[0].anchor_hash != b[0].anchor_hash


@pytest.mark.parametrize(
    "directive",
    [
        "phpcs:ignore Generic",
        "phpcs:ignore Generic.Metrics",
        "phpcs:ignore generic.metrics.cyclomaticcomplexity",
        "phpcs:ignore SlevomatCodingStandard.Complexity.Cognitive",
        "phpcs:ignore Acme.Functions.Nesting.Deep",
        "phpcs:ignore Acme.Functions.StaticFunction, Generic",
        "@phpstan-ignore complexity.tooHigh",
    ],
)
def test_declaration_body_edit_rebinds_for_standard_category_and_metric_codes(directive):
    base = _decl(directive, "public function m()")
    edited = _decl(directive, "public function m()", "if ($a) { if ($b) { return 2; } }")
    assert base.anchor_kind == "method_declaration"
    assert edited.anchor_hash != base.anchor_hash


@pytest.mark.parametrize(
    "directive",
    ["phpcs:ignore Magento2.Functions.StaticFunction", "@phpstan-ignore missingType.return", "@phpstan-ignore x"],
)
def test_declaration_body_edit_keeps_header_for_specific_codes(directive):
    base = _decl(directive, "public function m()")
    edited = _decl(directive, "public function m()", "if ($a) { if ($b) { return 2; } }")
    assert edited.anchor_hash == base.anchor_hash


def _hash(body: str) -> object:
    (p,), _, _ = _collect(_wrap(body))
    return p.anchor_hash


def test_phpcs_directive_on_a_later_row_of_a_trailing_block_ignores_the_following_row():
    # PHPCS 3.13.5 / 4.0.4 read a block comment row by row: the directive's own row decides (probe D9)
    def one(head: str, nxt: str) -> object:
        return _hash(f"        {head} /* note\n         * phpcs:ignore X.Y.Z */\n        {nxt}")

    base = one("x();", "y();")
    assert one("x();", "z(1);") != base  # the ignored row edited: rebound
    assert one("w(1);", "y();") == base  # the comment's start row is not covered


def test_phpstan_identifier_ignore_in_a_trailing_block_covers_the_start_row():
    # PHPStan 2.3.6 reads the comment as one token: a trailing one covers the row it starts on (probe D9)
    def one(head: str, nxt: str) -> object:
        return _hash(f"        {head} /* note\n         * @phpstan-ignore x.y */\n        {nxt}")

    base = one("x();", "y();")
    assert one("w(1);", "y();") != base
    assert one("x();", "z(1);") == base


@pytest.mark.parametrize("directive", ["phpcs:ignore X.Y.Z", "@phpstan-ignore-line"])
def test_directive_covering_a_row_inside_its_own_comment_fingerprints_that_row(directive):
    # PHPCS ignores the row after the directive's row, @phpstan-ignore-line the comment's end row: no code there
    from agent_ratchet.php.parser import EMPTY_LINE

    def one(nxt: str) -> object:
        return _hash(f"        /*\n         * {directive}\n         */\n        {nxt}")

    assert one("run();") == one("other(1);") == EMPTY_LINE


def test_anonymous_class_methods_get_their_own_symbols():
    require_php()
    from agent_ratchet.php.extract import analyze

    src = (
        "<?php\nnamespace N;\nclass A {\n"
        "    public function make() { return new class { public function x() {} }; }\n"
        "    public function x() {}\n}\n"
        "$y = new class { public function x() {} };\n"
    )
    assert analyze(src.encode(), "a.php").symbols == frozenset(
        {"N\\A", "N\\A::make", "N\\A::x", "N\\class@anonymous#1::x", "N\\class@anonymous#2::x"}
    )
    pts, _, _ = _collect(src.replace("public function make() { return", "public function make() {\n// phpcs:ignore X.Y.Z\nreturn"))
    pts2, _, _ = _collect(
        src.replace("{ public function x() {} }; }", "{ public function x() {\n// phpcs:ignore X.Y.Z\nrun(); } }; }")
    )
    assert [p.symbol for p in pts] == ["N\\A::make"]
    assert [p.symbol for p in pts2] == ["N\\class@anonymous#1::x"]
