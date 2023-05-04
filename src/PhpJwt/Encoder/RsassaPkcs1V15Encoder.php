<?php

declare(strict_types=1);

namespace PhpJwt\Encoder;

use PhpJwt;

class RsassaPkcs1V15Encoder extends AbstractEncoder
{
    public function getSignedToken(PhpJwt\JoseHeader $header, PhpJwt\JwtClaimsSet $claims, array $parameters = []): string
    {
        // TODO: implement
    }
}
