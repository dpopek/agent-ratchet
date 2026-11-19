"""PHPUnit weakening outside single test bodies: replaced tests, class-wide skips, abstract test classes (spec R5/R6)."""

from __future__ import annotations

import pytest
from php_support import require_php

TEST_PATH = "app/code/V/M/Test/Unit/XTest.php"
REMOVED, WEAKENED = "php_test_removed", "php_test_weakened"


def _cats(base: str, target: str) -> list[str]:
    require_php()
    from agent_ratchet.php.compare import compare_php_entry

    return [v.category for v in compare_php_entry(base.encode(), target.encode(), TEST_PATH, TEST_PATH, ())]


def _cls(methods: str, modifier: str = "") -> str:
    return (
        "<?php\nnamespace V\\M\\Test;\nuse PHPUnit\\Framework\\TestCase;\n"
        f"{modifier}class XTest extends TestCase\n{{\n{methods}}}\n"
    )


def _method(name: str, body: str, static: bool = False) -> str:
    return f"    public {'static ' if static else ''}function {name}(): void {{\n        {body}\n    }}\n"


VAT = _method("testChargesVat", "$this->assertSame(19, (new Calc())->vat(100));")


# --- (a) removed and added tests pair on payload AND body ------------------------------------------------


def test_deleted_test_replaced_by_unrelated_trivial_test_is_removed() -> None:
    assert _cats(_cls(VAT), _cls(_method("testNothing", "$this->assertTrue(true);"))) == [REMOVED]


def test_pure_rename_with_reformatted_identical_body_passes() -> None:
    target = _cls(_method("testVatIsCharged", "// same check\n        $this->assertSame( 19, (new Calc())->vat(100) );"))
    assert _cats(_cls(VAT), target) == []


def test_cross_file_move_needs_the_same_body() -> None:
    require_php()
    from agent_ratchet.php.compare import compare_php_tests_across
    from agent_ratchet.php.extract import PhpPlugin

    def tests(src: str, path: str):
        return [f for f in PhpPlugin().extract(src.encode(), path, {}) if f.kind == "php.test"]

    removed = tests(_cls(VAT), TEST_PATH)
    other = "app/code/V/M/Test/Unit/YTest.php"
    assert compare_php_tests_across(removed, tests(_cls(VAT).replace("XTest", "YTest"), other)) == []
    trivial = _cls(_method("testChargesVat", "$this->assertTrue(true);")).replace("XTest", "YTest")
    assert [v.category for v in compare_php_tests_across(removed, tests(trivial, other))] == [REMOVED]


# --- (b) a skip or incomplete in setUp / setUpBeforeClass weakens every test of the class ----------------


@pytest.mark.parametrize(
    "hook",
    [
        _method("setUp", "$this->markTestSkipped('later');"),
        _method("setup", "$this->markTestSkipped('later');"),  # PHP method names are case-insensitive
        _method("setUpBeforeClass", "self::markTestSkipped('later');", static=True),
        _method("setUp", "$this->markTestIncomplete('later');"),
    ],
)
def test_skip_added_in_setup_hook_is_weakened(hook: str) -> None:
    other = _method("testOther", "$this->assertTrue(false === false);")
    assert _cats(_cls(VAT + other), _cls(hook + VAT + other)) == [WEAKENED, WEAKENED]


def test_unchanged_setup_skip_passes() -> None:
    hook = _method("setUp", "if (!extension_loaded('intl')) { $this->markTestSkipped('intl'); }")
    base = _cls(hook + VAT)
    assert _cats(base, base.replace("vat(100)", "vat(200)")) == []


# --- (c) a test class made abstract no longer runs ------------------------------------------------------


def test_test_class_made_abstract_is_weakened() -> None:
    assert _cats(_cls(VAT), _cls(VAT, modifier="abstract ")) == [WEAKENED]


def test_already_abstract_test_class_passes() -> None:
    base = _cls(VAT, modifier="abstract ")
    assert _cats(base, base.replace("vat(100)", "vat(200)")) == []
