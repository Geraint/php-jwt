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
        if (!$privateKey instanceof OpenSSLAsymmetricKey) {
            throw new PhpJwt\Exception('private_key is not valid');
        }

        $headerEncoded = $this->base64UrlEncode($header->getJson());
        $payloadEncoded = $this->base64UrlEncode($claims->getJson());
        $data = "{$headerEncoded}.{$payloadEncoded}";

        $result = openssl_sign($data, $signature, $privateKey, $this->getAlgorithm($header->getAlg()));
        if ($result === false) {
            $errorMessage = openssl_error_string();
            throw new PhpJwt\Exception("Error signing token: {$errorMessage}");
        }

        $signatureEncoded = $this->base64UrlEncode($signature);
        return "{$headerEncoded}.{$payloadEncoded}.{$signatureEncoded}";
    }

    private function validateParameters(array $parameters): void
    {
        if (! array_key_exists(key: 'private_key', array: $parameters)) {
            throw new PhpJwt\Exception("Required parameter 'private_key' is not set");
        }
    }

    private function getAlgorithm(string $key): int
    {
        $algorithms = [
            'RS256' => OPENSSL_ALGO_SHA256,
            'RS384' => OPENSSL_ALGO_SHA384,
            'RS512' => OPENSSL_ALGO_SHA512,
        ];
        if (array_key_exists($key, $algorithms)) {
            return $algorithms[$key];
        }
        throw new PhpJwt\Exception("Unrecognised algorithm '{$key}'");
    }
}
