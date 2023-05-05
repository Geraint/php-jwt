<?php

declare(strict_types=1);

namespace PhpJwt;

use PHPUnit\Framework\TestCase;

/**
 * @covers \PhpJwt\JoseHeader
 */
class JoseHeaderTest extends TestCase
{
    /**
     * @test
     */
    public function canGetJson(): void
    {
        $parameters = [
            'alg' => 'RS256',
            'typ' => 'JWT',
        ];
        $expected = json_encode($parameters);
        $sut = new JoseHeader($parameters);
        $actual = $sut->getJson();
        $this->assertSame($expected, $actual);
    }

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
     * @dataProvider algProvider
     */
    public function canGetAlg(string $alg): void
    {
        $sut = new JoseHeader([
            'alg' => $alg,
        ]);
        $this->assertSame($alg, $sut->getAlg());
    }

    public static function algProvider(): array
    {
        return [
            'HS256' => [ 'alg' => 'HS256' ],
            'RS256' => [ 'alg' => 'RS256' ],
        ];
    }
}
