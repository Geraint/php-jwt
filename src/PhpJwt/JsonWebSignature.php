<?php

declare(strict_types=1);

namespace PhpJwt;

use PhpJwt\Encoder;

class JsonWebSignature
{
    public function __construct(private JoseHeader $header, private JwtClaimsSet $claims)
    {
    }

    public function getSignedToken(string $secret): string
    {
        $encoder = new Encoder\HmacEncoder($this->header, $this->claims);
        return $encoder->getSignedToken($secret);
    }
}
