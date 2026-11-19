<?php
namespace Acme\Shop\Model;

class Pricing
{
    // phpcs:ignore
    public function net(
        int $amount
    ): int {
        return round($amount * 1.23);
    }
}
