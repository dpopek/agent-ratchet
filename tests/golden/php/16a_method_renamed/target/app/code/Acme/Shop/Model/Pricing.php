<?php
namespace Acme\Shop\Model;

class Pricing
{
    public function netAmount(int $amount): int
    {
        // phpcs:ignore Generic.Sample.Rule
        return round($amount * 1.23);
    }

    public function gross(int $amount): int
    {
        return round($amount * 1.23);
    }
}
