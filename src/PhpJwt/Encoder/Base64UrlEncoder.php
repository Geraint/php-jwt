<?php

declare(strict_types=1);

namespace PhpJwt\Encoder;

class Base64UrlEncoder
{
    public function encode(string $data): string
    {
        return str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($data));
    }
}
