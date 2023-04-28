<?php

declare(strict_types=1);

namespace PhpJwt;

use PHPUnit\Framework\TestCase;

class JwtClaimsSetTest extends TestCase
{
    /**
     * @test
     */
    public function canSetClaims(): void
    {
        $claims = [
            'iss' => 'the issuer',
            'sub' => 'the subject',
            'aud' => 'the audience',
            'exp' => time(),
        ];
        $sut = new JwtClaimsSet($claims);
        $json = $sut->getJson();
        $decoded = json_decode($json);
        $this->assertIsObject($decoded);
        foreach ($claims as $key => $value) {
            $this->assertObjectHasProperty($key, $decoded);
            $this->assertSame($value, $decoded->$key);
        }
    }
}
