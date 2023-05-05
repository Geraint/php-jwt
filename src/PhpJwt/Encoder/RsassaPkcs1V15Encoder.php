<?php

declare(strict_types=1);

namespace PhpJwt\Encoder;

use OpenSSLAsymmetricKey;
use PhpJwt;

class RsassaPkcs1V15Encoder extends AbstractEncoder
{
    public function getSignedToken(PhpJwt\JoseHeader $header, PhpJwt\JwtClaimsSet $claims, array $parameters = []): string
    {
        $this->validateParameters($parameters);
        $privateKey = openssl_pkey_get_private($parameters['private_key']);
        assert($privateKey instanceof OpenSSLAsymmetricKey); // TODO: throw an exception, here

        $headerEncoded = $this->base64UrlEncode($header->getJson());
        $payloadEncoded = $this->base64UrlEncode($claims->getJson());
        $data = "{$headerEncoded}.{$payloadEncoded}";

        openssl_sign($data, $signature, $privateKey, OPENSSL_ALGO_SHA256); // TODO: check result is true

        $signatureEncoded = $this->base64UrlEncode($signature);
        return "{$headerEncoded}.{$payloadEncoded}.{$signatureEncoded}";
    }

    private function validateParameters(array $parameters): void
    {
        if (! array_key_exists(key: 'private_key', array: $parameters)) {
            throw new PhpJwt\Exception("Required parameter 'private_key' is not set");
        }
    }
}
