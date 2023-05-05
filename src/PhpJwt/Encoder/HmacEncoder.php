<?php

declare(strict_types=1);

namespace PhpJwt\Encoder;

use PhpJwt;

class HmacEncoder extends AbstractEncoder
{
    public function getSignedToken(PhpJwt\JoseHeader $header, PhpJwt\JwtClaimsSet $claims, array $parameters = []): string
    {
        $this->validateParameters($parameters);
        $headerEncoded = $this->base64UrlEncode($header->getJson());
        $payloadEncoded = $this->base64UrlEncode($claims->getJson());
        $algorithm = $this->getHmacAlgorithm($header->getAlg());
        $data = "{$headerEncoded}.{$payloadEncoded}";
        $signature = $this->base64UrlEncode(hash_hmac($algorithm, $data, $parameters['secret'], true));
        return "{$headerEncoded}.{$payloadEncoded}.{$signature}";
    }

    private function validateParameters(array $parameters): void
    {
        if (! array_key_exists(key: 'secret', array: $parameters)) {
            throw new PhpJwt\Exception("Required parameter 'secret' is not set");
        }
    }

    private function getHmacAlgorithm(string $key): string
    {
        $algorithms = [
            'HS256' => 'sha256',
            'HS384' => 'sha384',
            'HS512' => 'sha512',
        ];
        if (array_key_exists($key, $algorithms)) {
            return $algorithms[$key];
        }
        throw new PhpJwt\Exception("Unrecognised algorithm '{$key}'");
    }
}
