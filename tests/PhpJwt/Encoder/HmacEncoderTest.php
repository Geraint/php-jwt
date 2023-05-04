<?php

declare(strict_types=1);

namespace PhpJwt\Encoder;

use PHPUnit\Framework\TestCase;
use PhpJwt;

/**
 * @covers \PhpJwt\Encoder\HmacEncoder
 */
class HmacEncoderTest extends TestCase
{
    /**
     * @test
     * @dataProvider hmacAlgorithmProvider
     */
    public function canSignTokenWithHmacAlgorithms(string $alg, string $expected): void
    {
        $header = new PhpJwt\JoseHeader([
            'typ' => 'JWT',
            'alg' => $alg,
        ]);
        $claims = new PhpJwt\JwtClaimsSet([
            'sub'  => '1234567890',
            'name' => 'Joe Bloggs',
            'iat'  => 1516239022,
        ]);
        $sut = new HmacEncoder();

        $actual = $sut->getSignedToken($header, $claims, [
            'secret' => 'my top secret'
        ]);

        $this->assertSame($expected, $actual);
    }

    public static function hmacAlgorithmProvider(): array
    {
        return [
            'HS256' => [
                'alg'      => 'HS256',
                'expected' => <<<'END'
                eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvZSBCbG9nZ3MiLCJpYXQiOjE1MTYyMzkwMjJ9.90xiwm_yk7UO7BbabP0Bv2jM1d1Vh_kTU3NIO0cVsoU
                END,
            ],
            'HS384' => [
                'alg'      => 'HS384',
                'expected' => <<<'END'
                eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzM4NCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvZSBCbG9nZ3MiLCJpYXQiOjE1MTYyMzkwMjJ9.V0E0afUrbUFDXZBsnyjQUyF85h8dME9UiNevs1vluW6pVgS-vs8K17DQs4JEbtMV
                END,
            ],
            'HS512' => [
                'alg'      => 'HS512',
                'expected' => <<<'END'
                eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvZSBCbG9nZ3MiLCJpYXQiOjE1MTYyMzkwMjJ9.Gl_oH9h2p9YQKlBj5_3QZSTbPlINc8qEF-QA7TsebxXa6ojl9jqHx86zlqAeW2CA3vUMLRKbb6skLKIBz4ueiA
                END,
            ],
        ];
    }
}
