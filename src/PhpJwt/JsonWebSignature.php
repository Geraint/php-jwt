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
        $algorithm = $this->getHmacAlgorithm();
        $data = "{$headerEncoded}.{$payloadEncoded}";
        $signature = $this->base64UrlEncode(hash_hmac($algorithm, $data, $secret, true));
        return "{$headerEncoded}.{$payloadEncoded}.{$signature}";
    }

    private function getHmacAlgorithm(): string
    {
        $algorithms = [
            'HS256' => 'sha256',
            'HS384' => 'sha384',
            'HS512' => 'sha512',
        ];
        $key = $this->header->getAlg();
        if (array_key_exists($key, $algorithms)) {
            return $algorithms[$key];
        }
        throw new Exception("Unrecognised algorithm '{$key}'");
    }

    private function base64UrlEncode(string $text): string
    {
        return str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($text));
    }
}
