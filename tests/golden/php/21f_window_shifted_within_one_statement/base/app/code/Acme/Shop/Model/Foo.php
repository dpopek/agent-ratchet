<?php
function run($a, $b) {
    // phpcs:disable Generic.PHP.ForbiddenFunctions
    $x = bar(1, 2, 3, 4, 5, 6,
        // phpcs:enable
        sizeof($a));
    foo($x);
}
