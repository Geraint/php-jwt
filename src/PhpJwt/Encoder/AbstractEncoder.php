<?php

declare(strict_types=1);

namespace PhpJwt\Encoder;

use PhpJwt;

abstract class AbstractEncoder
{
    // FIXME: different algorithms might not need a secret, but rather a public/private key pair
    // abstract public function getSignedToken(PhpJwt\JoseHeader $header, PhpJwt\JwtClaimsSet $claims, string $secret): string;

    protected function base64UrlEncode(string $text): string
    {
        return str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($text));
    }
}
