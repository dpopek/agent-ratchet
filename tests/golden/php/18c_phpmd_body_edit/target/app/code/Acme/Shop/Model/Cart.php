<?php
namespace Acme\Shop\Model;

class Cart
{
    /** @SuppressWarnings(PHPMD.UnusedLocalVariable) */
    public function total(int $amount): int
    {
        $unused = 2;
        return $amount + 1;
    }
}
