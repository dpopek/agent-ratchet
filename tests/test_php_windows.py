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
