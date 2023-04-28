<?php

declare(strict_types=1);

namespace PhpJwt;

use PHPUnit\Framework\TestCase;

class JsonWebSignatureTest extends TestCase
{
    /**
     * @test
     */
    public function canSignToken(): void
    {
        $header = new JoseHeader([
            'typ' => 'JWT',
            'alg' => 'HS256'
        ]);
        $claims = new JwtClaimsSet([
            'sub'  => '1234567890',
            'name' => 'Joe Bloggs',
            'iat'  => 1516239022,
        ]);
        $sut = new JsonWebSignature($header, $claims);

        $expected = <<<'END'
        eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvZSBCbG9nZ3MiLCJpYXQiOjE1MTYyMzkwMjJ9.90xiwm_yk7UO7BbabP0Bv2jM1d1Vh_kTU3NIO0cVsoU
        END;

        $actual = $sut->getSignedToken('my top secret');

        $this->assertSame($expected, $actual);
    }
}
