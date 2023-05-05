<?php

declare(strict_types=1);

namespace PhpJwt;

use PHPUnit\Framework\TestCase;

/**
 * @covers \PhpJwt\Jwt
 */
class JwtTest extends TestCase
{
    /**
     * @test
     * @dataProvider getEncodedProvider
     */
    public function canGetEncoded(array $header, array $payload, array $parameters): void
    {
        $actual = Jwt::encode($header, $payload, $parameters);
        $this->assertMatchesRegularExpression('#^[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+$#', $actual);
    }

    public static function getEncodedProvider(): array
    {
        return [
            'HS256' => [
                'header'     => [
                    'alg'         => 'HS256',
                    'typ'         => 'JWT',
                ],
                'payload'    => [
                    'sub'         => '0123456789',
                    'name'        => 'the name',
                    'iat'         => time(),
                ],
                'parameters' => [
                    'secret'       => 'the shared secret',
                ],
            ],
            'RS256' => [
                'header'     => [
                    'alg'         => 'RS256',
                    'typ'         => 'JWT',
                ],
                'payload'    => [
                    'sub'         => '0123456789',
                    'name'        => 'the name',
                    'iat'         => time(),
                ],
                'parameters' => [
                    'private_key' => file_get_contents(__DIR__ . '/../private_key.pem'),
                ],
            ],
        ];
    }
}
