<?php
namespace Acme\Shop\Model;
class Foo {
    public function run($a) {
        $x = bar(
            1,
            sizeof($a)
        );
        // phpcs:disable Generic.PHP.ForbiddenFunctions
        foo($x);
    }
}
