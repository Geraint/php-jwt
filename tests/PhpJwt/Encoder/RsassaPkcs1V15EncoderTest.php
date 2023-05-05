<?php

declare(strict_types=1);

namespace PhpJwt\Encoder;

use PHPUnit\Framework\TestCase;
use PhpJwt;

/**
 * @covers \PhpJwt\Encoder\RsassaPkcs1V15Encoder
 */
class RsassaPkcs1V15EncoderTest extends TestCase
{
    /**
     * @test
     * @dataProvider parametersProvider
     */
    public function throwsExceptionIfPrivateKeysIsNotProvided(array $parameters): void
    {
        $this->expectException(PhpJwt\Exception::class);
        $header = $this->createStub(PhpJwt\JoseHeader::class);
        $claims = $this->createStub(PhpJwt\JwtClaimsSet::class);
        $sut = new RsassaPkcs1V15Encoder();
        $sut->getSignedToken($header, $claims, $parameters);
    }   

    public static function parametersProvider(): array
    {
        return [
            'no parameters' => [
                'parameters' => [
                ],
            ],
            'wrong parameters' => [
                'parameters' => [
                    'secret' => 'does not matter what this is',
                ],
            ],
        ];
    }

    /**
     * @test
     * @dataProvider rsassaAlgorithmProvider
     */
    public function canSignTokenWithRsassaAlgorithms(string $alg, string $expected): void
    {
        $header = new PhpJwt\JoseHeader([
            'alg' => $alg,
            'typ' => 'JWT',
        ]);
        $claims = new PhpJwt\JwtClaimsSet([
            'sub'  => '1234567890',
            'name' => 'Joe Bloggs',
            'iat'  => 1516239022,
        ]);
        $sut = new RsassaPkcs1V15Encoder();

        $actual = $sut->getSignedToken($header, $claims, [
            'private_key' => $this->getPrivateKey(),
        ]);

        $this->assertSame($expected, $actual);
    }

    public static function rsassaAlgorithmProvider(): array
    {
        return [
            'RS256' => [
                'alg'      => 'RS256',
                'expected' => <<<'END'
                eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvZSBCbG9nZ3MiLCJpYXQiOjE1MTYyMzkwMjJ9.EdE3Xc4_911RAnoVdz9hPwyAWHaKfZ14n7BZRq_0MFlPN_Dc7zhABI8UVBb8cDYLm7w-yV1CiPt05MLgt3l6TYPIJDMAdtcKJa9V1-hBQGCveTOqtt1-wct1Htd5ODJ3HYVEWsBe9s2OGcW3dvY8P-1ZgPaRj4LxGNf46_eB-XnEfscnCi5GdmkyI9kL2N_1SePaC_b_sKwG_WoIPttGlZNczBLZdkB2_1Eb6akmefL6LjM-J4mS9vBm11bYV0BMGNpQBTbjPsUblUjuiXT1f2-C_L_k8JusiTaPpqHyAk2tsHp44TTt4HvjOjufaPDioeGGpALNj3g522yeqmQUbg
                END,
            ],
        ];
    }

    private function getPrivateKey(): string
    {
        $path = realpath(__DIR__ . '/../..') . '/private_key.pem';
        return file_get_contents($path);
    }
}
