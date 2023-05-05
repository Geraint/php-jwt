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
    public function throwsExceptionIfPrivateKeyIsNotProvidedOrIsInvalid(array $parameters): void
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
            'invalid private key' => [
                'parameters' => [
                    'private_key' => 'this is not a valid key',
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
            'RS384' => [
                'alg'      => 'RS384',
                'expected' => <<<'END'
                eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvZSBCbG9nZ3MiLCJpYXQiOjE1MTYyMzkwMjJ9.YKPrlYE64n_KG5DjL83Q6LZEOJ3MFK4YHti4N10K068s10GDxhlrYfpkUJjkhZ_7AhT5KRBfEDZ__9AMngXhcTF0QzK14BtvXe8AL6jy5goX3-0LT0HLiqwVU691NKXF-qHiCE6ydSPV0gsvnLNLeAeP7AC1MEoy77IMZxBi0ifvoNsD5qkw5Dw7sk10QG1ASN21PiBDQ-wZzIcKJ6m5wGnw5QLkG-FKLxahm6kqHnkaCPIzgQkeI2BUwVHpjRXXjEIR6sPaqfHSWbzJrLbMAKyOBRgLFM3mk6WEYWrrXdAMoM8LESgRTvJbKdw6-9jrDsjeuHYABp4TBn2u82wSUQ
                END,
            ],
            'RS512' => [
                'alg'      => 'RS512',
                'expected' => <<<'END'
                eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvZSBCbG9nZ3MiLCJpYXQiOjE1MTYyMzkwMjJ9.I5Kr-zuHEEt2Dp6zXMmm6U1Gw4-S-PjaBUIAZXk_FA1Di6Fa-BO_3OAJ44cBfFoywG1oeCGiOvSsN3uR6oGkEWT3ZYOXZr51fqi_r4mB1REQoorNiYdkcxTKJLEFRwZi-P7cj_i5wBjSXyraY5-rPsXSYck4W03y63mRaKZLYUBNPl9SMdn0UqZYEz7tMTupJvuQ5dellFOGllrKOSIhLRHStwiEehPiNFAPF-WhVY9_EDHcXB4lfN8SCxYAOsZbSCHFi_CryrycGBlbPeaDITVjpwLgx2Gpm9UhZus1LFK-l_wLDJRPcZSUj2oQqe71sX8it0RgwRqnRzqhtgKQSA
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
