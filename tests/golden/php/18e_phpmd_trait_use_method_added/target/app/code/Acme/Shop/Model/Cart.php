<?php
namespace Acme\Shop\Model;

class Cart
{
    /** @SuppressWarnings(PHPMD) */
    use Totals;

    public function total(int $amount): int
    {
        $unused = 1;
        return $amount;
    }
}
