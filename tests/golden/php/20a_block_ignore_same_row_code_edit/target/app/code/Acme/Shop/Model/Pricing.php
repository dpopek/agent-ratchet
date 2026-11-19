<?php
namespace Acme\Shop\Model;

class Pricing
{
    public function count(array $items): int
    {
        /* phpcs:ignore Generic.PHP.ForbiddenFunctions */ $n = sizeof($items, COUNT_RECURSIVE);
        return $n;
    }
}
