<?php
namespace Acme\Shop\Model;

class Pricing
{
    // phpcs:ignore Generic.Sample.Rule
    protected function net(
        int $amount
    ): int {
        return round($amount * 1.23);
    }
}
