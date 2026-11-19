<?php
namespace Acme\Shop\Model;
class Foo {
    public function run($a, $b) {
        $x = bar(
            // phpcs:disable Generic.PHP.ForbiddenFunctions
            1, sizeof($a)
        );
        foo($x);
    }
}
