<?php
namespace Acme\Shop\Model;

class Cart
{
    /** @SuppressWarnings(PHPMD.UnusedLocalVariable) */
    public function net(int $amount): int
    {
        return $amount;
    }

    public function gross(int $amount): int
    {
        return $amount;
    }
}
