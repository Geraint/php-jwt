<?php

declare(strict_types=1);

namespace PhpJwt;

class JsonWebSignature
{
    public function __construct(private JoseHeader $header, private JwtClaimsSet $claims)
    {
    }

    public function getSignedToken(string $secret): string
    {
        $headerEncoded = $this->base64UrlEncode($this->header->getJson());
        $payloadEncoded = $this->base64UrlEncode($this->claims->getJson());
        $algorithm = 'sha256';
        $data = "{$headerEncoded}.{$payloadEncoded}";
        $signature = $this->base64UrlEncode(hash_hmac($algorithm, $data, $secret, true));
        return "{$headerEncoded}.{$payloadEncoded}.{$signature}";
    }

    private function base64UrlEncode(string $text): string
    {
        return str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($text));
    }
}
