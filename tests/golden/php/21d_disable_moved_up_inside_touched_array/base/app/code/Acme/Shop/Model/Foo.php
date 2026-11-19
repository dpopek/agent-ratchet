<?php
namespace Acme\Shop\Model;
class Foo {
    public function run($a) {
        return [
            1,
            sizeof($a),
            2,
            // phpcs:disable Generic.PHP.ForbiddenFunctions
        ];
    }
}
