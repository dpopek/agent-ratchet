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
    assert w.closed is True and len(w.statements) == 2


def test_phpcs_disabled_typo_is_unknown_tool():
    pts, _, _ = _collect(_wrap("        // phpcs:disabled\n        run();"))
    (p,) = pts
    assert p.tool == "phpcs-unknown" and p.anchor_kind is None and p.anchor_hash is None


def test_window_closed_and_statements():
    src = "<?php\n$a = 1;\n// phpcs:disable X.Y\n$b = 2;\nfoo();\n// phpcs:enable X.Y\n$c = 3;\n"
    _, wins, _ = _collect(src)
    (w,) = wins
    assert (w.closed, w.codes, w.symbol, w.line) == (True, ("X.Y",), "<file>", 3)
    assert len(w.statements) == 2 and list(w.statements) == sorted(w.statements)


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


_SIG = "<?php\nnamespace A\\B;\nclass C {\n    // phpcs:ignore X.Y\n    public function m(\n        int $a\n    ): int {\n        return {body};\n    }\n}\n"


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


def test_same_row_block_comment_targets_next_row():
    base, _, _ = _collect(_wrap("        // @phpstan-ignore-next-line\n        foo();\n        ok();"))
    tgt, _, _ = _collect(_wrap("        /* @phpstan-ignore-next-line */ foo();\n        bad();"))
    assert base[0].anchor_hash != tgt[0].anchor_hash
    base, _, _ = _collect(_wrap("        // phpcs:ignore X.Y\n        foo();\n        ok();"))
    tgt, _, _ = _collect(_wrap("        /* phpcs:ignore X.Y */ foo();\n        bad();"))
    assert base[0].anchor_hash != tgt[0].anchor_hash


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
    for directive in ("@phpstan-ignore Code.X", "@phpstan-ignore-next-line", "phpcs:ignore A.B"):
        base = _decl(directive, "public function m(\n        int $a\n    ): int")
        assert base.anchor_kind == "method_declaration"
        for sig in (
            "public function m(\n        int $a, int $b\n    ): int",
            "public function m(\n        int $a\n    )",
        ):
            assert _decl(directive, sig).anchor_hash != base.anchor_hash, (directive, sig)
    base = _decl("phpcs:ignore A.B", "public\n    function m()")
    assert _decl("phpcs:ignore A.B", "public\n    static function m()").anchor_hash != base.anchor_hash
    coded = _decl("phpcs:ignore A.B", "public function m()")
    assert _decl("phpcs:ignore A.B", "public function m()", "return 2;").anchor_hash == coded.anchor_hash


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
