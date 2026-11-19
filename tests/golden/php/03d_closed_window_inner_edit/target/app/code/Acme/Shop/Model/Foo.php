<?php
namespace Acme\Shop\Model;
class Foo {
    public function run() {
// phpcs:disable Generic.Sample.Rule
a(1);
b();
// phpcs:enable Generic.Sample.Rule
z();
    }
}
