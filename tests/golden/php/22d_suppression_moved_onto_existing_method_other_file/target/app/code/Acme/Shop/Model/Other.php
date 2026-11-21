<?php
namespace Acme\Shop\Model;

class Other
{
    public function keep(array $data): string
    {
        // phpcs:ignore Generic.Sample.Rule
        return md5(serialize($data));
    }
}
