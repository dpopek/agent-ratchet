<?php
namespace Acme\Shop\Model;

class Other
{
    public function keep(array $data): string
    {
        return md5(serialize($data));
    }
}
