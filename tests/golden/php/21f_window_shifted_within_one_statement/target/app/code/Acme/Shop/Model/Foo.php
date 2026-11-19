<?php
function run($a, $b) {
    $x = bar(1, 2, 3, 4, 5, 6,
        // phpcs:disable Generic.PHP.ForbiddenFunctions
        sizeof($a));
    // phpcs:enable
    foo($x);
}
