<?php
function run($a, $b) {
    // phpcs:disable Generic.PHP.ForbiddenFunctions
    $n += sizeof($a);
    // phpcs:enable
    foo();
    bar();
    // phpcs:disable Generic.PHP.ForbiddenFunctions
    $n += sizeof($a);
    // phpcs:enable
}
