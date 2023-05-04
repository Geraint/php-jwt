<?php

declare(strict_types=1);

namespace PhpJwt\Encoder;

use PhpJwt;

class HmacEncoder extends AbstractEncoder
{
    public function getSignedToken(PhpJwt\JoseHeader $header, PhpJwt\JwtClaimsSet $claims, array $parameters = []): string
    {
        $secret = $parameters['secret'];
        $headerEncoded = $this->base64UrlEncode($header->getJson());
        $payloadEncoded = $this->base64UrlEncode($claims->getJson());
        $algorithm = $this->getHmacAlgorithm($header->getAlg());
        $data = "{$headerEncoded}.{$payloadEncoded}";
        $signature = $this->base64UrlEncode(hash_hmac($algorithm, $data, $secret, true));
        return "{$headerEncoded}.{$payloadEncoded}.{$signature}";
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
        throw new Exception("Unrecognised algorithm '{$key}'");
    }
}
