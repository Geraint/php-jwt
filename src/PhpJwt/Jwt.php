<?php

declare(strict_types=1);

namespace PhpJwt;

use PhpJwt\Encoder;

use function PHPUnit\Framework\stringContains;

class Jwt
{
    private function __construct()
    {
    }

    public static function encode(array $header, array $payload, array $parameters): string
    {
        $joseHeader = new JoseHeader($header);
        $claims     = new JwtClaimsSet($payload);
        $signature  = new JsonWebSignature(new Encoder\EncoderFactory());
        return $signature->getSignedToken($joseHeader, $claims, $parameters);
    }
}
