<?php

declare(strict_types=1);

namespace PhpJwt;

class JwtClaimsSet
{
    public function __construct(private array $claims)
    {
    }

    public function getJson(): string
    {
        return json_encode($this->claims, JSON_THROW_ON_ERROR);
    }
}
