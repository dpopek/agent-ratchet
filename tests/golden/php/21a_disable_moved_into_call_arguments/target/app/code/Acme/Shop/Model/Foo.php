<?php
namespace Acme\Shop\Model;
class Foo {
    public function run($a) {
        $x = bar(
            1,
            // phpcs:disable Generic.PHP.ForbiddenFunctions
            sizeof($a)
        );
        foo($x);
    }
}
