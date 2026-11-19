<?php
namespace Acme\Shop\Model;
class Foo {
    public function run() {
$a = first();
// @phpstan-ignore sample.code
$b = second($a);
third($b);
    }
}
