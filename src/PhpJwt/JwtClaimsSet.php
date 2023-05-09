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
        return json_encode((object) $this->claims, JSON_THROW_ON_ERROR);
    }
}
