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

    /**
     * @test
     * @dataProvider verifyProvider
     */
    public function canVerify(string $token, array $parameters, bool $expected): void
    {
        $actual = Jwt::verify($token, $parameters);
        $this->assertSame($expected, $actual);
    }

    public static function verifyProvider(): array
    {
        return [
            'a completely corrupt token' => [
                'token'      => 'this is not a valid token',
                'parameters' => [],
                'expected'   => false,
            ],
            'a valid(-ish) looking token, but actually invalid' => [
                'token'      => 'A.B.C',
                'parameters' => [],
                'expected'   => false,
            ],
            'a valid HS256 token' => [
                'token'      => 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvZSBCbG9nZ3MiLCJpYXQiOjE1MTYyMzkwMjJ9.cWPf6g4AMgzx5CorjSp8bK1ywXIW5o2dM7bBdUMHhlw',
                'parameters' => [ 'secret' => 'my top secret' ],
                'expected'   => true,
            ],
            'a valid HS256 token but the wrong shared secret' => [
                'token'      => 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvZSBCbG9nZ3MiLCJpYXQiOjE1MTYyMzkwMjJ9.cWPf6g4AMgzx5CorjSp8bK1ywXIW5o2dM7bBdUMHhlw',
                'parameters' => [ 'secret' => 'the wrong secret' ],
                'expected'   => false,
            ],
            'a HS256 token with a bad signature' => [
                'token'      => 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvZSBCbG9nZ3MiLCJpYXQiOjE1MTYyMzkwMjJ9.fOoBaR',
                'parameters' => [ 'secret' => 'my top secret' ],
                'expected'   => false,
            ],
            'a valid RS256 token' => [
                'token'      => 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvZSBCbG9nZ3MiLCJpYXQiOjE1MTYyMzkwMjJ9.EdE3Xc4_911RAnoVdz9hPwyAWHaKfZ14n7BZRq_0MFlPN_Dc7zhABI8UVBb8cDYLm7w-yV1CiPt05MLgt3l6TYPIJDMAdtcKJa9V1-hBQGCveTOqtt1-wct1Htd5ODJ3HYVEWsBe9s2OGcW3dvY8P-1ZgPaRj4LxGNf46_eB-XnEfscnCi5GdmkyI9kL2N_1SePaC_b_sKwG_WoIPttGlZNczBLZdkB2_1Eb6akmefL6LjM-J4mS9vBm11bYV0BMGNpQBTbjPsUblUjuiXT1f2-C_L_k8JusiTaPpqHyAk2tsHp44TTt4HvjOjufaPDioeGGpALNj3g522yeqmQUbg',
                'parameters' => [ 'public_key' => file_get_contents(__DIR__ . '/../public_key.pem') ],
                'expected'   => true,
            ], 
            'a valid RS256 token, but the public key is invalid' => [
                'token'      => 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvZSBCbG9nZ3MiLCJpYXQiOjE1MTYyMzkwMjJ9.EdE3Xc4_911RAnoVdz9hPwyAWHaKfZ14n7BZRq_0MFlPN_Dc7zhABI8UVBb8cDYLm7w-yV1CiPt05MLgt3l6TYPIJDMAdtcKJa9V1-hBQGCveTOqtt1-wct1Htd5ODJ3HYVEWsBe9s2OGcW3dvY8P-1ZgPaRj4LxGNf46_eB-XnEfscnCi5GdmkyI9kL2N_1SePaC_b_sKwG_WoIPttGlZNczBLZdkB2_1Eb6akmefL6LjM-J4mS9vBm11bYV0BMGNpQBTbjPsUblUjuiXT1f2-C_L_k8JusiTaPpqHyAk2tsHp44TTt4HvjOjufaPDioeGGpALNj3g522yeqmQUbg',
                'parameters' => [ 'public_key' => 'this is not a valid public key' ],
                'expected'   => false,
            ], 
            'a valid RS384 token' => [
                'token'      => 'eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvZSBCbG9nZ3MiLCJpYXQiOjE1MTYyMzkwMjJ9.YKPrlYE64n_KG5DjL83Q6LZEOJ3MFK4YHti4N10K068s10GDxhlrYfpkUJjkhZ_7AhT5KRBfEDZ__9AMngXhcTF0QzK14BtvXe8AL6jy5goX3-0LT0HLiqwVU691NKXF-qHiCE6ydSPV0gsvnLNLeAeP7AC1MEoy77IMZxBi0ifvoNsD5qkw5Dw7sk10QG1ASN21PiBDQ-wZzIcKJ6m5wGnw5QLkG-FKLxahm6kqHnkaCPIzgQkeI2BUwVHpjRXXjEIR6sPaqfHSWbzJrLbMAKyOBRgLFM3mk6WEYWrrXdAMoM8LESgRTvJbKdw6-9jrDsjeuHYABp4TBn2u82wSUQ',
                'parameters' => [ 'public_key' => file_get_contents(__DIR__ . '/../public_key.pem') ],
                'expected'   => true,
            ], 
            'a valid RS512 token' => [
                'token'      => 'eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvZSBCbG9nZ3MiLCJpYXQiOjE1MTYyMzkwMjJ9.I5Kr-zuHEEt2Dp6zXMmm6U1Gw4-S-PjaBUIAZXk_FA1Di6Fa-BO_3OAJ44cBfFoywG1oeCGiOvSsN3uR6oGkEWT3ZYOXZr51fqi_r4mB1REQoorNiYdkcxTKJLEFRwZi-P7cj_i5wBjSXyraY5-rPsXSYck4W03y63mRaKZLYUBNPl9SMdn0UqZYEz7tMTupJvuQ5dellFOGllrKOSIhLRHStwiEehPiNFAPF-WhVY9_EDHcXB4lfN8SCxYAOsZbSCHFi_CryrycGBlbPeaDITVjpwLgx2Gpm9UhZus1LFK-l_wLDJRPcZSUj2oQqe71sX8it0RgwRqnRzqhtgKQSA',
                'parameters' => [ 'public_key' => file_get_contents(__DIR__ . '/../public_key.pem') ],
                'expected'   => true,
            ], 
        ];
    }
}
