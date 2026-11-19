<?php
namespace Acme\Shop\Model;

class Cart
{
    /** @SuppressWarnings(PHPMD.ExcessiveParameterList) */
    public function __construct(private int $amount, private int $quantity)
    {
    }
}
