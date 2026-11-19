"""PHPUnit test identity (spec R5): classes, methods, assertion and expectation counts, data providers."""

from __future__ import annotations

from php_support import require_php


def _tests(src: str, path: str = "app/code/V/M/Test/Unit/FooTest.php"):
    require_php()
    from agent_ratchet.php.parser import parse_php
    from agent_ratchet.php.phpunit import collect_tests

    return collect_tests(parse_php(src.encode()), path)


def _cls(body: str, head: str = "") -> str:
    return f"<?php\nnamespace V\\M\\Test;\nuse PHPUnit\\Framework\\TestCase;\n{head}\nclass FooTest extends TestCase\n{{\n{body}\n}}\n"


def test_assertion_forms_counted() -> None:
    body = """
    public function testA(): void {
        $this->assertTrue(true);
        self::assertSame(1, 1);
        static::assertEquals(1, 1);
        parent::assertNull(null);
        \\PHPUnit\\Framework\\Assert::assertCount(1, [1]);
        Assert::assertNotNull(1);
        $f = function () { $this->assertFalse(false); };
        $other->assertSomething();
        Other::assertSomething();
        assert(true);
    }"""
    (t,) = _tests(_cls(body))
    assert (t.class_fqn, t.method, t.assertions) == ("V\\M\\Test\\FooTest", "testA", 7)


def test_expects_and_expect_exception_names() -> None:
    body = """
    public function testB(): void {
        $m->expects($this->once())->method('a');
        $m->expects($this->never())->method('b');
        $this->expectException(\\Foo::class);
        $this->expectExceptionMessage('x');
        $this->expectExceptionCode(1);
        $this->expectExceptionMessageMatches('/x/');
        $this->expectExceptionObject(new \\Foo());
        $this->expectExceptionMessage('y');
    }"""
    (t,) = _tests(_cls(body))
    assert t.expects == 2
    assert t.expect_exception == (
        "expectException",
        "expectExceptionCode",
        "expectExceptionMessage",
        "expectExceptionMessage",
        "expectExceptionMessageMatches",
        "expectExceptionObject",
    )


def test_skip_incomplete_counted() -> None:
    body = """
    public function testC(): void {
        $this->markTestSkipped('a');
        if (x()) { self::markTestSkipped('b'); }
        $this->markTestIncomplete('c');
    }"""
    (t,) = _tests(_cls(body))
    assert (t.skips, t.incompletes) == (2, 1)


def test_data_provider_annotation_and_attribute() -> None:
    head = "use PHPUnit\\Framework\\Attributes\\{DataProvider as DP, DataProviderExternal};"
    body = """
    /**
     * @dataProvider provA
     * @dataProvider Other\\Cls::provB
     */
    public function testD(): void {}

    #[DP('provC'), DataProviderExternal(Other::class, 'provD')]
    public function testE(): void {}

    #[\\PHPUnit\\Framework\\Attributes\\DataProvider('provF')]
    public function testF(): void {}"""
    d, e, f = _tests(_cls(body, head))
    assert d.data_providers == ("Other\\Cls::provB", "provA")
    assert e.data_providers == ("Other::provD", "provC")
    assert f.data_providers == ("provF",)


def test_test_detection_via_use_alias() -> None:
    src = "<?php\nnamespace N;\nuse PHPUnit\\Framework\\TestCase as Base;\nclass X extends Base { public function testA() { $this->assertTrue(1); } }\n"
    (t,) = _tests(src, "src/X.php")
    assert (t.class_fqn, t.method, t.assertions) == ("N\\X", "testA", 1)
    src2 = "<?php\nclass Y extends \\PHPUnit\\Framework\\TestCase { public function testA() {} }\n"
    assert len(_tests(src2, "src/Y.php")) == 1


def test_name_ending_in_test_needs_test_dir() -> None:
    src = "<?php\nclass FooTest { public function testA() {} }\n"
    assert len(_tests(src, "app/code/V/M/Test/Unit/FooTest.php")) == 1
    assert len(_tests(src, "app/code/V/M/tests/FooTest.php")) == 1
    assert _tests(src, "app/code/V/M/Model/FooTest.php") == []


def test_test_annotation_and_attribute_methods() -> None:
    head = "use PHPUnit\\Framework\\Attributes\\Test;"
    body = """
    /** @test */
    public function itWorks(): void {}
    /** @testdox something */
    public function notATest(): void {}
    #[Test]
    public function viaAttribute(): void {}
    #[\\PHPUnit\\Framework\\Attributes\\Test]
    public function viaFqnAttribute(): void {}
    private function testPrivate(): void {}
    protected function testProtected(): void {}
    public function helper(): void {}
    public function testPlain(): void {}
    public function testAbstractLike();"""
    got = [t.method for t in _tests(_cls(body, head).replace("class FooTest", "abstract class FooTest"))]
    assert got == ["itWorks", "viaAttribute", "viaFqnAttribute", "testPlain"]


def test_non_test_class_ignored() -> None:
    src = "<?php\nclass Helper { public function testA() { $this->assertTrue(1); } }\ninterface I { public function testB(); }\n"
    assert _tests(src, "app/code/V/M/Test/Unit/Helper.php") == []


def test_line_is_one_based_method_line() -> None:
    (t,) = _tests(_cls("    public function testA(): void {}"))
    assert t.line == 7
