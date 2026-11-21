<?php
namespace Acme\Shop\Model;

class TokenA
{
    public function name(): string
    {
        return 'a';
    }

    public function token(array $data): string
    {
        // phpcs:ignore Generic.Sample.Rule
        return md5(serialize($data));
    }
}
