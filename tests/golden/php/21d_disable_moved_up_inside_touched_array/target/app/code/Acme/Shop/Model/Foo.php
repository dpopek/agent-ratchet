<?php
namespace Acme\Shop\Model;
class Foo {
    public function run($a) {
        return [ // phpcs:disable Generic.PHP.ForbiddenFunctions
            1,
            sizeof($a),
            2,
        ];
    }
}
