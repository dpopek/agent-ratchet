<?php
namespace Acme\Shop\Model;

class Pricing
{
    public function net(int $amount): int
    {
        // phpcs:ignore Generic.Sample.Rule
        return round($amount * 1.23);
    }
}
