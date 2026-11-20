<?php
namespace Acme\Shop\Model;

class Finder
{
    public function find(string $date, int $days): array
    {
        $items = $this->collection->create()
            ->addFieldToFilter('created_at', [
                'lt' => date(
                    'Y-m-d',
                    strtotime($date . " -$days days"), // phpcs:ignore Generic.Sample.Rule
                ),
            ]);
        $items->addFieldToFilter('status', ['nin' => ['x']]);
        return $items;
    }
}
