<?php

declare(strict_types=1);

namespace PhpJwt\Encoder;

use PhpJwt;

class RsassaPkcs1V15Encoder extends AbstractEncoder
{
    public function getSignedToken(PhpJwt\JoseHeader $header, PhpJwt\JwtClaimsSet $claims, array $parameters = []): string
    {
        $this->validateParameters($parameters);
        // TODO implement
    }

    private function validateParameters(array $parameters): void
    {
        if (! array_key_exists(key: 'private_key', array: $parameters)) {
            throw new PhpJwt\Exception("Required parameter 'private_key' is not set");
        }
    }
}
