<?php

declare(strict_types=1);

namespace PhpJwt;

use stdClass;

class JwtClaimsSet
{
    public function __construct(private array $claims)
    {
    }

    public function getJson(): string
    {
        $object = new stdClass();
        foreach ($this->claims as $key => $value) {
            $object->$key = $value;
        }
        return json_encode($object, JSON_THROW_ON_ERROR);
    }
}
