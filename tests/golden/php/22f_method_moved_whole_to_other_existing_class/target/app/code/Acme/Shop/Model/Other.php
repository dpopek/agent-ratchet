<?php
namespace Acme\Shop\Model;

class Other
{
    public function keep(): int
    {
        return 1;
    }

    public function token(array $data): string
    {
        // phpcs:ignore Generic.Sample.Rule
        return md5(serialize($data));
    }
}
