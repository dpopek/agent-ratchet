<?php
namespace Acme\Shop\Checkout\Model;

class Cart
{
    private array $items = [];

    public function add(string $sku, int $qty): void
    {
        // phpcs:ignore Generic.Sample.Rule
        $this->items[$sku] = ($this->items[$sku] ?? 0) + $qty;
        // @phpstan-ignore foo.bar
        $this->recount();
    }

    public function remove(string $sku): void
    {
        // phpcs:disable Generic.Sample.Other
        unset($this->items[$sku]);
        // phpcs:enable Generic.Sample.Other
        $this->recount();
        // phpcs:ignore Generic.Sample.Rule
        $this->items = array_values($this->items);
    }

    public function total(): int
    {
        return array_sum($this->items);
    }

    private function recount(): void
    {
        $this->items = array_filter($this->items);
    }
}
