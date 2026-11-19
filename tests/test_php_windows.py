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


def test_window_sliding_to_another_copy_of_a_statement_is_expanded() -> None:
    # round 4 ruling: no slide compensation. PHPCS [7] -> [3]: the copy on row 7 becomes suppressed (probed on 3 and 4)
    base = _FN.format(body=f"    // phpcs:disable {_SIZEOF}\n    $n = sizeof($a);\n    // phpcs:enable\n    d();\n    $n = sizeof($a);")
    target = _FN.format(body=f"    $n = sizeof($a);\n    d();\n    // phpcs:disable {_SIZEOF}\n    $n = sizeof($a);\n    // phpcs:enable")
    assert _cats(base, target) == [EXPANDED]


# --- I2 residual round 3: covered TARGET tokens aligned to BASE tokens must have been covered ------------

_ROUND3 = {
    'S1': (
        '<?php\nfunction run($a, $b) {\n    // phpcs:disable Generic.PHP.ForbiddenFunctions\n    $x = bar(1, 2, 3, 4, 5, 6,\n        // phpcs:enable\n        sizeof($a));\n    foo($x);\n}\n',
        '<?php\nfunction run($a, $b) {\n    $x = bar(1, 2, 3, 4, 5, 6,\n        // phpcs:disable Generic.PHP.ForbiddenFunctions\n        sizeof($a));\n    // phpcs:enable\n    foo($x);\n}\n',
    ),
    'S2': (
        '<?php\nfunction run($a, $b) {\n    // phpcs:disable Generic.PHP.ForbiddenFunctions\n    a();\n    // phpcs:enable\n    // phpcs:disable Generic.PHP.ForbiddenFunctions\n    $x = bar(1,\n        // phpcs:enable\n        sizeof($a));\n    z();\n}\n',
        '<?php\nfunction run($a, $b) {\n    // phpcs:disable Generic.PHP.ForbiddenFunctions\n    a();\n    $x = bar(1,\n        sizeof($a));\n    // phpcs:enable\n    z();\n    y();\n}\n',
    ),
    'S4': (
        '<?php\nfunction run($a, $b) {\n    if ($a\n        ==\n        $b) { // phpcs:disable Squiz.Operators.ComparisonOperatorUsage\n        d();\n    }\n}\n',
        '<?php\nfunction run($a, $b) {\n    if ($a\n        // phpcs:disable Squiz.Operators.ComparisonOperatorUsage\n        ==\n        $b) {\n        e();\n    }\n}\n',
    ),
    'S5': (
        '<?php\nfunction run(\n    $a = 1,\n    $b\n) {\n    // phpcs:disable PEAR.Functions.ValidDefaultValue\n    d();\n}\n',
        '<?php\nfunction run(\n    // phpcs:disable PEAR.Functions.ValidDefaultValue\n    $a = 1,\n    $b\n) {\n    e();\n}\n',
    ),
    'S11': (
        '<?php\nfunction run($a, $b) {\n    $n = sizeof($a);\n    // phpcs:disable Generic.PHP.ForbiddenFunctions\n    foo();\n}\n',
        '<?php\nfunction run($a, $b) {\n    // phpcs:disable Generic.PHP.ForbiddenFunctions\n    $n = sizeof(($a));\n    foo();\n}\n',
    ),
    'S12': (
        '<?php\nnamespace A\\B;\n// phpcs:disable PSR2.Namespaces.NamespaceDeclaration\nuse C\\D;\nclass K {}\n',
        '<?php\n// phpcs:disable PSR2.Namespaces.NamespaceDeclaration\nnamespace A\\B;\nuse C\\D;\nclass K {}\n',
    ),
    'H': (
        '<?php\nfunction run($a, $b) {\n    $x = bar(\n        1,\n        sizeof($a)\n    ); // phpcs:disable Generic.PHP.ForbiddenFunctions\n    foo($x);\n}\n',
        '<?php\nfunction run($a, $b) {\n    $x = bar(\n        1,\n        // phpcs:disable Generic.PHP.ForbiddenFunctions\n        sizeof($a, 0)\n    );\n    foo($x);\n}\n',
    ),
}


@pytest.mark.parametrize("case", sorted(_ROUND3))
def test_existing_code_newly_covered_is_expanded_whatever_else_changed(case: str) -> None:
    # bounds moved within one statement, windows merged, the enclosing code edited, the pulled-in code edited,
    # or rows outside every anchor (probed on PHPCS 3 and 4)
    assert _cats(*_ROUND3[case]) == [EXPANDED]



# --- I2 residual round 4: no compensation; inline HTML rows are tokens (probed on PHPCS 3 and 4) ---------------

_ROUND4 = {
    'PF1': (
        '<?php\nfunction run($a, $b) {\n    // phpcs:disable Generic.PHP.ForbiddenFunctions\n    $n += sizeof($a);\n    // phpcs:enable\n    foo();\n    // phpcs:disable Generic.PHP.ForbiddenFunctions\n    bar();\n    // phpcs:enable\n    $n += sizeof($a);\n}\n',
        '<?php\nfunction run($a, $b) {\n    // phpcs:disable Generic.PHP.ForbiddenFunctions\n    $n += sizeof($a);\n    // phpcs:enable\n    foo();\n    bar();\n    // phpcs:disable Generic.PHP.ForbiddenFunctions\n    $n += sizeof($a);\n    // phpcs:enable\n}\n',
        'php',
    ),
    'PF2': (
        '<?php\nclass K\n{\n    public function a($a)\n    {\n        // phpcs:disable Generic.PHP.ForbiddenFunctions\n        $n = sizeof($a);\n        // phpcs:enable\n        return $n;\n    }\n\n    public function b($a)\n    {\n        $n = sizeof($a);\n        // phpcs:disable Generic.PHP.ForbiddenFunctions\n        foo();\n        // phpcs:enable\n        return $n;\n    }\n}\n',
        '<?php\nclass K\n{\n    public function a($a)\n    {\n        // phpcs:disable Generic.PHP.ForbiddenFunctions\n        $n = sizeof($a);\n        // phpcs:enable\n        return $n;\n    }\n\n    public function b($a)\n    {\n        // phpcs:disable Generic.PHP.ForbiddenFunctions\n        $n = sizeof($a);\n        // phpcs:enable\n        foo();\n        return $n;\n    }\n}\n',
        'php',
    ),
    'DC1': (
        '<?php\nfunction run($a, $b) {\n    // phpcs:disable Generic.PHP.ForbiddenFunctions\n    $n += sizeof($a);\n    // phpcs:enable\n    $n += sizeof($a);\n    foo();\n    // phpcs:disable Generic.PHP.ForbiddenFunctions\n    bar();\n    // phpcs:enable\n    $n += sizeof($a);\n    return $n;\n}\n',
        '<?php\nfunction run($a, $b) {\n    $n += sizeof($a);\n    // phpcs:disable Generic.PHP.ForbiddenFunctions\n    $n += sizeof($a);\n    // phpcs:enable\n    foo();\n    // phpcs:disable Generic.PHP.ForbiddenFunctions\n    bar();\n    $n += sizeof($a);\n    // phpcs:enable\n    return $n;\n}\n',
        'php',
    ),
    'SL1': (
        "<?php\nfunction run($a, $b) {\n    // phpcs:disable Generic.Files.LineLength\n    $result = $this->collectionFactory->create()->addFieldToFilter('id', $id);\n    // phpcs:enable\n    if ($a) {\n        if ($b) {\n            $result = $this->collectionFactory->create()->addFieldToFilter('id', $id);\n        }\n    }\n}\n",
        "<?php\nfunction run($a, $b) {\n    $result = $this->collectionFactory->create()->addFieldToFilter('id', $id);\n    if ($a) {\n        if ($b) {\n            // phpcs:disable Generic.Files.LineLength\n            $result = $this->collectionFactory->create()->addFieldToFilter('id', $id);\n            // phpcs:enable\n        }\n    }\n}\n",
        'php',
    ),
    'SL2': (
        '<?php\nfunction run($a) {\n    if ($a) {\n        a();\n    // phpcs:disable Generic.WhiteSpace.ScopeIndent\n    }\n    // phpcs:enable\n    if ($a) {\n        b();\n      }\n}\n',
        '<?php\nfunction run($a) {\n    if ($a) {\n        a();\n    }\n    if ($a) {\n        b();\n      // phpcs:disable Generic.WhiteSpace.ScopeIndent\n      }\n      // phpcs:enable\n}\n',
        'php',
    ),
    'PH1': (
        '<div>\n<p>xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx</p>\n<?php // phpcs:disable Generic.Files.LineLength ?>\n<p>xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx</p>\n<?php // phpcs:enable ?>\n</div>\n',
        '<div>\n<?php // phpcs:disable Generic.Files.LineLength ?>\n<p>xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx</p>\n<p>xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx</p>\n<?php // phpcs:enable ?>\n</div>\n',
        'phtml',
    ),
    'PH2': (
        '<?php // phpcs:disable Generic.Files.LineLength ?>\n<p>xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx</p>\n<?php // phpcs:enable ?>\n<p>xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx</p>\n</div>\n',
        '<?php // phpcs:disable Generic.Files.LineLength ?>\n<p>xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx</p>\n<p>xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx</p>\n<?php // phpcs:enable ?>\n</div>\n',
        'phtml',
    ),
    'S7': (
        '<p>xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx</p>\n<?php // phpcs:disable Generic.Files.LineLength ?>\n<p>x</p>\n',
        '<?php // phpcs:disable Generic.Files.LineLength ?>\n<p>xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx</p>\n<p>x</p>\n',
        'phtml',
    ),
}

_ROUND4_PASS = {
    'PHC1': (
        '<div>\n<?php // phpcs:disable Generic.Files.LineLength ?>\n<p>xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx</p>\n<?php // phpcs:enable ?>\n<p>y</p>\n</div>\n',
        '<div>\n<?php // phpcs:disable Generic.Files.LineLength ?>\n<p>xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx</p>\n<p>new xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx</p>\n<?php // phpcs:enable ?>\n<p>y</p>\n</div>\n',
        'phtml',
    ),
    'PHC2': (
        '<div>\n<?php // phpcs:disable Generic.Files.LineLength ?>\n<p>xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx</p>\n<?php // phpcs:enable ?>\n<p>y</p>\n</div>\n',
        '<h1>new</h1>\n<div>\n<?php // phpcs:disable Generic.Files.LineLength ?>\n<p>xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx</p>\n<?php // phpcs:enable ?>\n<p>y</p>\n</div>\n',
        'phtml',
    ),
    'PHC3': (
        '<div>\n<?php // phpcs:disable Generic.Files.LineLength ?>\n<p>xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx</p>\n<?php // phpcs:enable ?>\n<p>y</p>\n</div>\n',
        '<div>\n<?php // phpcs:disable Generic.Files.LineLength ?>\n<p>xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx</p>\n<?php // phpcs:enable ?>\n<p>z</p>\n</div>\n',
        'phtml',
    ),
    'NC2': (
        '<?php\nfunction run($a, $b) {\n    // phpcs:disable Generic.PHP.ForbiddenFunctions\n    foo();\n    // phpcs:enable\n    $n += sizeof($a);\n}\n',
        '<?php\nfunction run($a, $b) {\n    // phpcs:disable Generic.PHP.ForbiddenFunctions\n    foo();\n    $m = sizeof($b);\n    // phpcs:enable\n    $n += sizeof($a);\n}\n',
        'php',
    ),
}


def _cats_ext(base: str, target: str, ext: str) -> list[str]:
    require_php()
    from agent_ratchet.php.compare import compare_php_entry

    path = PATH.removesuffix(".php") + "." + ext
    return [v.category for v in compare_php_entry(base.encode(), target.encode(), path, path, ())]


@pytest.mark.parametrize("case", sorted(_ROUND4))
def test_covered_rows_released_elsewhere_never_offset_new_coverage(case: str) -> None:
    # PF: a byte-identical twin window; DC: one released row, two grown windows; SL: slide onto a row that differs
    # only in whitespace; PH/S7: a bound tag moved across inline HTML, either direction
    assert _cats_ext(*_ROUND4[case]) == [EXPANDED]


@pytest.mark.parametrize("case", sorted(_ROUND4_PASS))
def test_new_code_or_moved_windows_with_their_rows_still_pass(case: str) -> None:
    assert _cats_ext(*_ROUND4_PASS[case]) == []


# --- I2 residual round 5: bound tags, bound recognition and inline HTML granularity (probed on PHPCS 3 and 4) ----

_ROUND5 = {
    'TG1': (
        '<div>\n<?php\n// phpcs:disable Generic.PHP.CharacterBeforePHPOpeningTag\nfoo();\n?>\n</div>\n',
        '<div>\n<?php // phpcs:disable Generic.PHP.CharacterBeforePHPOpeningTag\nfoo();\n?>\n</div>\n',
        'phtml',
    ),
    'TG1b': (
        '<p>a</p>\n\t<?php\n// phpcs:disable Generic.WhiteSpace.DisallowTabIndent\nfoo();\n?>\n',
        '<p>a</p>\n\t<?php // phpcs:disable Generic.WhiteSpace.DisallowTabIndent\nfoo();\n?>\n',
        'phtml',
    ),
    'TG2b': (
        '<?php\r\n// phpcs:disable Generic.Files.LineEndings\r\nfoo();\r\n',
        '<?php // phpcs:disable Generic.Files.LineEndings\r\nfoo();\r\n',
        'php',
    ),
    'BC1b': (
        '<?php // phpcs:disable Generic.WhiteSpace.DisallowTabIndent ?>\n<p>a</p>\n<?php // phpcs:enable ?>\n\t<?php /* see phpcs: docs */ ?>\n',
        '<?php // phpcs:disable Generic.WhiteSpace.DisallowTabIndent ?>\n<p>a</p>\n\t<?php /* see phpcs: docs */ ?>\n<?php // phpcs:enable ?>\n',
        'phtml',
    ),
    'HE1': (
        '<div>\n<p>xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx</p>\n<?php // phpcs:disable Generic.Files.LineLength ?>\n<p>z</p>\n<?php // phpcs:enable ?>\n</div>\n',
        '<div>\n<?php // phpcs:disable Generic.Files.LineLength ?>\n<p>xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx</p>\n<p>z</p>\n<?php // phpcs:enable ?>\n</div>\n',
        'phtml',
    ),
    'HE2': (
        '<div>\n<p>xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx</p>\n<p>xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx</p>\n<?php // phpcs:disable Generic.Files.LineLength ?>\n<p>z</p>\n<?php // phpcs:enable ?>\n</div>\n',
        '<div>\n<?php // phpcs:disable Generic.Files.LineLength ?>\n<p>xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx</p><p>xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx</p>\n<p>z</p>\n<?php // phpcs:enable ?>\n</div>\n',
        'phtml',
    ),
    'PH3': (
        '<p>xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx</p>\n<?php\n// phpcs:disable Generic.Files.LineLength\n?>\n<p>x</p>\n',
        '<?php\n// phpcs:disable Generic.Files.LineLength\n?>\n<p>xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx</p>\n<p>x</p>\n',
        'phtml',
    ),
    'PH4': (
        '<?php // phpcs:disable Generic.Files.LineLength ?>\n<p>a</p>\n<?php\n// phpcs:enable\n?>\n<p>xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx</p>\n<p>x</p>\n',
        '<?php // phpcs:disable Generic.Files.LineLength ?>\n<p>a</p>\n<p>xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx</p>\n<?php\n// phpcs:enable\n?>\n<p>x</p>\n',
        'phtml',
    ),
}

_ROUND5_PASS = {
    'NZ1': (
        '<ul>\n<li>a</li>\n<?php // phpcs:disable Generic.Files.LineLength ?>\n<li>xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx</li>\n<?php // phpcs:enable ?>\n</ul>\n',
        '<ul>\n<li>b</li>\n<?php // phpcs:disable Generic.Files.LineLength ?>\n<li>xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx</li>\n<li>c</li>\n<?php // phpcs:enable ?>\n</ul>\n',
        'phtml',
    ),
    'NZ2': (
        '<ul>\n<?php // phpcs:disable Generic.Files.LineLength ?>\n<li>xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx</li>\n<?php // phpcs:enable ?>\n<li>b</li>\n</ul>\n',
        '<ul>\n<li>new</li>\n<li>b</li>\n<?php // phpcs:disable Generic.Files.LineLength ?>\n<li>xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx</li>\n<?php // phpcs:enable ?>\n</ul>\n',
        'phtml',
    ),
}


@pytest.mark.parametrize("case", sorted(_ROUND5))
def test_tag_rows_html_edits_and_bound_blocks_pulled_in_are_expanded(case: str) -> None:
    # TG: a disable joined onto an open-tag row; BC1b: `phpcs:` mid-text is no bound; HE: an HTML row edited or
    # merged while pulled in; PH3/PH4: a multi-row `<?php // phpcs:… ?>` block moved across HTML
    assert _cats_ext(*_ROUND5[case]) == [EXPANDED]


@pytest.mark.parametrize("case", sorted(_ROUND5_PASS))
def test_new_html_and_windows_moved_among_repeated_tags_pass(case: str) -> None:
    assert _cats_ext(*_ROUND5_PASS[case]) == []


# --- I2 residual round 6: bound tags on another row, attributes inside one-tag HTML rows (PHPCS 3 and 4) ------

_ROUND6 = {
    'TG1c': (
        '<p>a</p>\n\t<?php\n// phpcs:disable Generic.WhiteSpace.DisallowTabIndent\n?>\n<p>b</p>\n',
        '<p>a</p>\n\t<?php // phpcs:disable Generic.WhiteSpace.DisallowTabIndent\n?>\n<p>b</p>\n',
        'phtml',
    ),
    'TG2c': (
        '<?php\r\n// phpcs:disable Generic.Files.LineEndings\r\n?>\r\n<p>x</p>\r\n',
        '<?php // phpcs:disable Generic.Files.LineEndings\r\n?>\r\n<p>x</p>\r\n',
        'phtml',
    ),
    'HS1': (
        '<div>\n<img src="/media/catalog/xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.png" alt="a">\n<?php // phpcs:disable Generic.Files.LineLength ?>\n<p>z</p>\n<?php // phpcs:enable ?>\n</div>\n',
        '<div>\n<?php // phpcs:disable Generic.Files.LineLength ?>\n<img src="/media/catalog/xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.png" alt="b">\n<p>z</p>\n<?php // phpcs:enable ?>\n</div>\n',
        'phtml',
    ),
}

_ROUND6_PASS = {
    'BU2': (
        '<?php // phpcs:disable Generic.PHP.ForbiddenFunctions ?>\n<p>a</p>\n\t<?php // phpcs:enable Generic.PHP.ForbiddenFunctions ?>\n<?php // phpcs:disable Generic.WhiteSpace.DisallowTabIndent ?>\n<p>b</p>\n',
        '<?php // phpcs:disable Generic.PHP.ForbiddenFunctions ?>\n<p>a</p>\n<?php // phpcs:disable Generic.WhiteSpace.DisallowTabIndent ?>\n\t<?php // phpcs:enable Generic.PHP.ForbiddenFunctions ?>\n<p>b</p>\n',
        'phtml',
    ),
}


@pytest.mark.parametrize("case", sorted(_ROUND6))
def test_bound_tag_rows_and_edited_tag_attributes_pulled_in_are_expanded(case: str) -> None:
    # TG1c/TG2c: a disable joined onto the `<?php` row of a block holding only the directive; HS1: an attribute
    # edited in a one-tag HTML row pulled in
    assert _cats_ext(*_ROUND6[case]) == [EXPANDED]


@pytest.mark.parametrize("case", sorted(_ROUND6_PASS))
def test_bound_unit_moved_whole_under_another_window_passes(case: str) -> None:
    # BU2: PHPCS 3 and 4 report nothing on either side; the tag sits on its own bound's row in both
    assert _cats_ext(*_ROUND6_PASS[case]) == []
