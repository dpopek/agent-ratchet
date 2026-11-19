<?php
namespace Acme\Shop\Model;
class Foo {
    public function run() {
$a = first();
$b = second($a);
// @phpstan-ignore sample.code
third($b);
    }
}
