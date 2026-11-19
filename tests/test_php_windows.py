"""PHPCS code-list extent, legacy window bounds and row-based window coverage (spec R4/R6, probed on PHPCS 3 and 4)."""

from __future__ import annotations

import pytest
from php_support import require_php

PATH = "app/code/V/M/Model/X.php"
EXPANDED = "php_suppression_range_expanded"


def _collect(src: str):
    require_php()
    from agent_ratchet.php.directives import collect
    from agent_ratchet.php.parser import parse_php

    return collect(parse_php(src.encode()))


def _cats(base: str, target: str) -> list[str]:
    require_php()
    from agent_ratchet.php.compare import compare_php_entry

    return [v.category for v in compare_php_entry(base.encode(), target.encode(), PATH, PATH, ())]


def _m(body: str) -> str:
    return f"<?php\nnamespace V\\M;\nclass X {{\n    public function run() {{\n{body}\n    }}\n}}\n"


# --- C1: a PHPCS code list runs to the end of the comment line, whatever follows -------------------

_CARRIERS = ("phpcs:enable", "@codingStandardsIgnoreEnd")


@pytest.mark.parametrize("carrier", _CARRIERS)
def test_phpcs_ignore_codes_run_past_a_later_match(carrier: str) -> None:
    (p,), _, _ = _collect(_m(f"// phpcs:ignore Foo.Bar.Baz, {carrier}, Generic.PHP.ForbiddenFunctions\n$x = sizeof($a);"))
    assert p.codes == tuple(sorted(("Foo.Bar.Baz", carrier, "Generic.PHP.ForbiddenFunctions")))


@pytest.mark.parametrize("carrier", _CARRIERS)
def test_phpcs_ignore_widened_through_a_carrier_is_added(carrier: str) -> None:
    base = _m("// phpcs:ignore Foo.Bar.Baz\n$x = sizeof($a);")
    target = _m(f"// phpcs:ignore Foo.Bar.Baz, {carrier}, Generic.PHP.ForbiddenFunctions\n$x = sizeof($a);")
    assert _cats(base, target) == ["php_suppression_added"]


@pytest.mark.parametrize("carrier", _CARRIERS)
def test_phpcs_disable_widened_through_a_carrier_is_expanded(carrier: str) -> None:
    base = _m("// phpcs:disable Foo.Bar.Baz\n$x = sizeof($a);")
    target = _m(f"// phpcs:disable Foo.Bar.Baz, {carrier}, Generic.PHP.ForbiddenFunctions\n$x = sizeof($a);")
    assert _cats(base, target) == [EXPANDED]


def test_phpcs_enable_codes_run_past_a_later_match() -> None:
    src = "<?php\n// phpcs:disable A.B\n$a = 1;\n// phpcs:enable C.D, @codingStandardsIgnoreEnd, A.B\n$b = 2;\n"
    _, (w,), _ = _collect(src)
    assert (w.closed, len(w.statements)) == (True, 1)  # PHPCS 3 and 4 close it (probed)


def test_other_tools_keep_their_own_extent_after_a_phpcs_match() -> None:
    pts, _, _ = _collect(_m("// phpcs:ignore A.B.C @phpstan-ignore foo.bar\n$x = 1;"))
    assert sorted((p.tool, p.codes) for p in pts) == [("phpcs", ("A.B.C @phpstan-ignore foo.bar",)), ("phpstan", ("foo.bar",))]


# --- I1: PHPCS 4 ignores every legacy annotation, so `@codingStandardsIgnoreEnd` closes no window ------------


@pytest.mark.parametrize("opener", ["// phpcs:disable A.B", "// @codingStandardsIgnoreStart"])
def test_legacy_end_closes_no_window(opener: str) -> None:
    _, (w,), _ = _collect(f"<?php\n{opener}\n$a = 1;\n// @codingStandardsIgnoreEnd\n$b = 2;\n")
    assert (w.closed, len(w.statements)) == (False, 2)


def test_enable_swapped_for_legacy_end_is_expanded() -> None:
    base = _m("// phpcs:disable A.B\na();\n// phpcs:enable\nz();")
    target = _m("// phpcs:disable A.B\na();\n// @codingStandardsIgnoreEnd\nz();")
    assert _cats(base, target) == [EXPANDED]


def test_legacy_start_moved_over_existing_statement_is_expanded() -> None:
    base = _m("y();\n// @codingStandardsIgnoreStart\na();\n// @codingStandardsIgnoreEnd\nz();")
    target = _m("// @codingStandardsIgnoreStart\ny();\na();\n// @codingStandardsIgnoreEnd\nz();")
    assert _cats(base, target) == [EXPANDED]


def test_nested_statement_pulled_in_with_its_container_edited_is_expanded() -> None:
    # Anchors include nested statements: editing the container must not hide the unchanged inner one.
    base = _m("if ($c) {\n    a();\n    b();\n}\n// phpcs:disable A.B\nz();")
    target = _m("// phpcs:disable A.B\nif ($c) {\n    a();\n    b2();\n}\nz();")
    assert _cats(base, target) == [EXPANDED]


# --- I2: PHPCS suppresses whole rows from the disable row up to (not including) the enable row ------------


def test_trailing_disable_covers_its_own_row() -> None:
    _, (w,), _ = _collect("<?php\n$y = sizeof($a); // phpcs:disable A.B\nfoo();\n")
    assert len(w.statements) == 2


def test_trailing_enable_row_is_not_covered() -> None:
    _, (w,), _ = _collect("<?php\n// phpcs:disable A.B\na();\nz(); // phpcs:enable\n")
    assert (w.closed, len(w.statements)) == (True, 1)  # PHPCS 3/4 report `z()` on the enable row (probed)


def test_disable_inside_a_multi_line_statement_covers_that_statement() -> None:
    _, (w,), _ = _collect("<?php\n$x = bar(\n    1,\n    // phpcs:disable A.B\n    sizeof($a)\n);\nfoo();\n")
    assert len(w.statements) == 2


def test_disable_moved_into_call_arguments_is_expanded() -> None:  # w1
    base = _m("$x = bar(\n    1,\n    sizeof($a)\n);\n// phpcs:disable Generic.PHP.ForbiddenFunctions\nfoo();")
    target = _m("$x = bar(\n    1,\n    // phpcs:disable Generic.PHP.ForbiddenFunctions\n    sizeof($a)\n);\nfoo();")
    assert _cats(base, target) == [EXPANDED]


def test_disable_moved_into_returned_array_literal_is_expanded() -> None:
    base = _m("return [\n    1,\n    sizeof($a),\n];\n// phpcs:disable Generic.PHP.ForbiddenFunctions")
    target = _m("return [ // phpcs:disable Generic.PHP.ForbiddenFunctions\n    1,\n    sizeof($a),\n];")
    assert _cats(base, target) == [EXPANDED]


def test_disable_moved_onto_the_end_of_an_existing_row_is_expanded() -> None:  # w2
    base = _m("$y = sizeof($a);\n// phpcs:disable Generic.PHP.ForbiddenFunctions\nfoo();")
    target = _m("$y = sizeof($a); // phpcs:disable Generic.PHP.ForbiddenFunctions\nfoo();")
    assert _cats(base, target) == [EXPANDED]


def test_window_also_covers_the_enclosing_declarations() -> None:
    _, (w,), _ = _collect(_m("// phpcs:disable A.B\na();"))
    assert len(w.statements) == 3  # a(), the method and the class all meet the window's rows


def test_enable_moved_onto_the_end_of_the_next_row_passes() -> None:
    base = _m("// phpcs:disable A.B\na();\n// phpcs:enable\nz();")
    target = _m("// phpcs:disable A.B\na();\nz(); // phpcs:enable")
    assert _cats(base, target) == []


# --- I2 residual: a disable moved inside a statement the BASE window already met -------------------------

_FN = "<?php\nfunction run($a) {{\n{body}\n}}\n"
_SIZEOF = "Generic.PHP.ForbiddenFunctions"


def test_disable_moved_up_inside_an_already_touched_call_is_expanded() -> None:  # p1
    base = _FN.format(body=f"    $x = bar(\n        1,\n        sizeof($a)\n    ); // phpcs:disable {_SIZEOF}\n    foo($x);")
    target = _FN.format(body=f"    $x = bar(\n        1,\n        // phpcs:disable {_SIZEOF}\n        sizeof($a)\n    );\n    foo($x);")
    assert _cats(base, target) == [EXPANDED]


def test_disable_moved_up_inside_an_already_touched_array_is_expanded() -> None:  # p2
    base = _FN.format(body=f"    return [\n        1,\n        sizeof($a),\n        2,\n        // phpcs:disable {_SIZEOF}\n    ];")
    target = _FN.format(body=f"    return [ // phpcs:disable {_SIZEOF}\n        1,\n        sizeof($a),\n        2,\n    ];")
    assert _cats(base, target) == [EXPANDED]


def test_window_moved_with_its_unchanged_rows_passes() -> None:
    block = f"    // phpcs:disable {_SIZEOF}\n    $n = sizeof($a);\n    // phpcs:enable\n"
    base = _FN.format(body=f"    a();\n{block}    b();")
    target = _FN.format(body=f"{block}    a();\n    b();")
    assert _cats(base, target) == []


def test_new_rows_under_an_unchanged_window_pass() -> None:
    base = _FN.format(body=f"    // phpcs:disable {_SIZEOF}\n    $n = sizeof($a);\n    // phpcs:enable\n    if ($a) {{\n        b();\n    }}")
    target = base.replace("$n = sizeof($a);", "$n = sizeof($a);\n    if ($n) {\n        c($n);\n    }")
    assert _cats(base, target) == []


# --- I2 residual round 2: leaf tokens of an unchanged statement newly covered (reflow-invariant) ---------

_ROUND2 = {
    'N': (
        '<?php\nfunction run($a, $b) {\n    $x = bar(\n        1,\n        sizeof($a)\n    ); // phpcs:disable Generic.PHP.ForbiddenFunctions\n    foo($x);\n}\n',
        '<?php\nfunction run($a, $b) {\n    $x = bar(\n        // phpcs:disable Generic.PHP.ForbiddenFunctions\n        1, sizeof($a)\n    );\n    foo($x);\n}\n',
    ),
    'O': (
        '<?php\nfunction run($a, $b) {\n    $x = bar(\n        1,\n        sizeof($a)\n    ); // phpcs:disable Generic.PHP.ForbiddenFunctions\n    foo($x);\n}\n',
        '<?php\nfunction run($a, $b) {\n    $x = bar(\n        1,\n        // phpcs:disable Generic.PHP.ForbiddenFunctions\n        sizeof(\n            $a)\n    );\n    foo($x);\n}\n',
    ),
    'P': (
        '<?php\nfunction run($a, $b) {\n    return [\n        1,\n        sizeof($a),\n        2,\n        // phpcs:disable Generic.PHP.ForbiddenFunctions\n    ];\n}\n',
        '<?php\nfunction run($a, $b) {\n    return [ // phpcs:disable Generic.PHP.ForbiddenFunctions\n        1, sizeof($a), 2,\n    ];\n}\n',
    ),
    'C': (
        '<?php\nfunction run($a, $b) {\n    $y = $b\n        .\n        @\n        foo(); // phpcs:disable Generic.PHP.NoSilencedErrors\n    d();\n}\n',
        '<?php\nfunction run($a, $b) {\n    $y = $b\n        .\n        // phpcs:disable Generic.PHP.NoSilencedErrors\n        @\n        foo();\n    d();\n}\n',
    ),
    'D': (
        '<?php\nfunction run($a, $b) {\n    if ($a\n        ==\n        $b) { // phpcs:disable Squiz.Operators.ComparisonOperatorUsage\n        d();\n    }\n}\n',
        '<?php\nfunction run($a, $b) {\n    if ($a\n        // phpcs:disable Squiz.Operators.ComparisonOperatorUsage\n        ==\n        $b) {\n        d();\n    }\n}\n',
    ),
    'E': (
        '<?php\nfunction run($a, $b) {\n    if ($a\n        =\n        $b) { // phpcs:disable Generic.CodeAnalysis.AssignmentInCondition\n        d();\n    }\n}\n',
        '<?php\nfunction run($a, $b) {\n    if ($a\n        // phpcs:disable Generic.CodeAnalysis.AssignmentInCondition\n        =\n        $b) {\n        d();\n    }\n}\n',
    ),
    'A': (
        '<?php\nfunction run($a, $b) {\n    if ($a) {\n        b();\n        // phpcs:disable Generic.WhiteSpace.ScopeIndent\n        c();\n        // phpcs:enable\n      }\n    d();\n}\n',
        '<?php\nfunction run($a, $b) {\n    if ($a) {\n        b();\n        // phpcs:disable Generic.WhiteSpace.ScopeIndent\n        c();\n      }\n        // phpcs:enable\n    d();\n}\n',
    ),
    'B': (
        '<?php\nfunction run($a, $b) {\n    if ($a) {\n        // phpcs:disable Squiz.WhiteSpace.SuperfluousWhitespace\n        c();\n        // phpcs:enable\n    }   \n    d();\n}\n',
        '<?php\nfunction run($a, $b) {\n    if ($a) {\n        // phpcs:disable Squiz.WhiteSpace.SuperfluousWhitespace\n        c();\n    }   \n    // phpcs:enable\n    d();\n}\n',
    ),
}


@pytest.mark.parametrize("case", sorted(_ROUND2))
def test_unchanged_statement_with_more_covered_tokens_is_expanded(case: str) -> None:
    # N/O/P: rows reflowed by whitespace only; C/D/E: operator-only rows; A/B: a closing `}` row (probed on PHPCS 3 and 4)
    assert _cats(*_ROUND2[case]) == [EXPANDED]


def test_window_sliding_to_another_copy_of_a_statement_passes() -> None:
    base = _FN.format(body=f"    // phpcs:disable {_SIZEOF}\n    $n = sizeof($a);\n    // phpcs:enable\n    d();\n    $n = sizeof($a);")
    target = _FN.format(body=f"    $n = sizeof($a);\n    d();\n    // phpcs:disable {_SIZEOF}\n    $n = sizeof($a);\n    // phpcs:enable")
    assert _cats(base, target) == []
