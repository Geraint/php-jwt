<?php

declare(strict_types=1);

namespace PhpJwt;

use PHPUnit\Framework\TestCase;

class JoseHeaderTest extends TestCase
{
    /**
     * @test
     */
    public function typeIsJwt(): void
    {
        $sut = new JoseHeader([
            'alg' => 'none',
        ]);
        $json = $sut->getJson();
        $decoded = json_decode($json);
        $this->assertIsObject($decoded);
        $this->assertObjectHasProperty('typ', $decoded);
        $this->assertSame('JWT', $decoded->typ);
    }

    /**
     * @test
     * @dataProvider ctyProvider
     */
    public function canSetCty(array $parameters, bool $expected): void
    {
        $sut = new JoseHeader($parameters);
        $json = $sut->getJson();
        $decoded = json_decode($json);
        $this->assertSame($expected, property_exists($decoded, 'cty'));
    }

    public static function ctyProvider(): array
    {
        return [
            'no cty' => [
                $parameters = [ 'alg' => 'none' ],
                $expected   = false,
            ],
            'cty' => [
                $parameters = [  'alg' => 'none', 'cty' => 'JWT' ],
                $expected   = true,
            ],
        ];
    }

    /**
     * @test
     */
    public function ctyMustBeJwt(): void
    {
        $this->expectexception(exception::class);
        $this->expectexceptionmessage('"cty"');
        $sut = new JoseHeader([ 'alg' => 'none', 'cty' => 'invalid value']);
    }

    /**
     * @test
     */
    public function canReplicateClaimsAsHeaderParameters(): void
    {
        $sut = new JoseHeader([
            'alg' => 'none',
            'iss' => 'foo',
            'sub' => 'bar',
            'aud' => 'baz',
        ]);
        $json = $sut->getJson();
        $decoded = json_decode($json);
        $this->assertObjectHasProperty('iss', $decoded);
        $this->assertSame('foo', $decoded->iss);
        $this->assertObjectHasProperty('sub', $decoded);
        $this->assertSame('bar', $decoded->sub);
        $this->assertObjectHasProperty('aud', $decoded);
        $this->assertSame('baz', $decoded->aud);
    }

    /**
     * @test
     */
    public function mustHaveAlg(): void
    {
        $this->expectexception(exception::class);
        $this->expectexceptionmessage('"alg"');
        $sut = new JoseHeader([]);
    }

    /**
     * @test
     */
    public function canGetAlg(): void
    {
        $sut = new JoseHeader([
            'alg' => 'HS256',
        ]);
        $this->assertSame('HS256', $sut->getAlg());
    }
}
