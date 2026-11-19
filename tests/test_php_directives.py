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
