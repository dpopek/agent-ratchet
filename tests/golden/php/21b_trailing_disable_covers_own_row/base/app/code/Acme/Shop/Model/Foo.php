<?php
namespace Acme\Shop\Model;
class Foo {
    public function run($a) {
        $y = sizeof($a);
        // phpcs:disable Generic.PHP.ForbiddenFunctions
        foo($y);
    }
}
