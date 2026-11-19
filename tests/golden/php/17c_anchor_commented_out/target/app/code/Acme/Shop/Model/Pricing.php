<?php
namespace Acme\Shop\Model;

class Pricing
{
    public function net(int $amount): int
    {
        // phpcs:ignore Generic.Sample.Rule
        // if ($amount > 0) {
        //     return 0;
        // }
        return round($amount * 1.23);
    }
}
