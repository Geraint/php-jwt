<?php

declare(strict_types=1);

namespace PhpJwt\Encoder;

use PhpJwt;

abstract class AbstractEncoder
{
    abstract public function getSignedToken(PhpJwt\JoseHeader $header, PhpJwt\JwtClaimsSet $claims, array $parameters = []): string;

    protected function base64UrlEncode(string $text): string
    {
        return str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($text));
    }
}
