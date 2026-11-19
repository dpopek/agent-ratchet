<?php
namespace Acme\Shop\Model;

class Cart
{
    public function net(int $amount): int
    {
        return $amount;
    }

    /** @SuppressWarnings(PHPMD.UnusedLocalVariable) */
    public function gross(int $amount): int
    {
        return $amount;
    }
}
