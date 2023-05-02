<?php

declare(strict_types=1);

namespace PhpJwt\Encoder;

use PhpJwt;

abstract class AbstractEncoder
{
    abstract public function getSignedToken(string $secret): string;

    public function __construct(protected PhpJwt\JoseHeader $header, protected PhpJwt\JwtClaimsSet $claims)
    {
    }

    protected function base64UrlEncode(string $text): string
    {
        return str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($text));
    }
}
