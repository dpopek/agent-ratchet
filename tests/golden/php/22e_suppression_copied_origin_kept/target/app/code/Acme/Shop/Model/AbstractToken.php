<?php
namespace Acme\Shop\Model;

abstract class AbstractToken
{
    public function token(array $data): string
    {
        // phpcs:ignore Generic.Sample.Rule
        return md5(serialize($data));
    }
}
