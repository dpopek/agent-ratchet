<?php
function run($a, $b) {
    // phpcs:disable Generic.PHP.ForbiddenFunctions
    $n += sizeof($a);
    // phpcs:enable
    foo();
    // phpcs:disable Generic.PHP.ForbiddenFunctions
    bar();
    // phpcs:enable
    $n += sizeof($a);
}
