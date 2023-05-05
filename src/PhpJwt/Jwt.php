<?php

declare(strict_types=1);

namespace PhpJwt;

use JsonException;
use OpenSSLAsymmetricKey;
use PhpJwt\Encoder;

class Jwt
{
    private function __construct()
    {
    }

    public static function encode(array $header, array $payload, array $parameters): string
    {
        $joseHeader = new JoseHeader($header);
        $claims     = new JwtClaimsSet($payload);
        $signature  = new JsonWebSignature(new Encoder\EncoderFactory());
        return $signature->getSignedToken($joseHeader, $claims, $parameters);
    }

    public static function verify(string $token, array $parameters): bool
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            return false;
        }

        try {
            $header  = self::decodeHeader($parts[0]);
            $payload = self::decodePayload($parts[1]);
        } catch (JsonException $e) {
            return false;
        }

        if (str_starts_with($header['alg'], 'HS')) {
            $expected = self::encode($header, $payload, $parameters);
            return $expected === $token;
        }

        if (str_starts_with($header['alg'], 'RS')) {
            $publicKey = openssl_pkey_get_public($parameters['public_key']);
            if (!$publicKey instanceof OpenSSLAsymmetricKey) {
                return false;
            }
            $data = "{$parts[0]}.{$parts[1]}";
            $signature = self::base64UrlDecode($parts[2]);
            $algorithm = self::getRsAlgorithm($header['alg']);
            $result = openssl_verify($data, $signature, $publicKey, $algorithm);
            return $result === 1;
        }
    }

    private static function decodeHeader(string $encodedHeader): array
    {
        $json = self::base64UrlDecode($encodedHeader);
        return json_decode($json, true, flags: JSON_THROW_ON_ERROR);
    }

    private static function decodePayload(string $encodedPayload): array
    {
        $json = self::base64UrlDecode($encodedPayload);
        return json_decode($json, true, flags: JSON_THROW_ON_ERROR);
    }

    private static function base64UrlDecode(string $data): string
    {
        $urlUnsafeData = strtr($data, '-_', '+/');
        $paddedData = str_pad($urlUnsafeData, strlen($data) % 4, '=', STR_PAD_RIGHT);
        return base64_decode($paddedData);
    }

    private static function getRsAlgorithm(string $key): int
    {
        $algorithms = [
            'RS256' => OPENSSL_ALGO_SHA256,
            'RS384' => OPENSSL_ALGO_SHA384,
            'RS512' => OPENSSL_ALGO_SHA512,
        ];
        if (array_key_exists($key, $algorithms)) {
            return $algorithms[$key];
        }
        throw new Exception("Unrecognised algorithm '{$key}'");
    }
}
