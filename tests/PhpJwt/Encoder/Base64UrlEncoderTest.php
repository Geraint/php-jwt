<?php

declare(strict_types=1);

namespace PhpJwt\Encoder;

use PHPUnit\Framework\TestCase;
use PhpJwt;

/**
 * @covers \PhpJwt\Encoder\Base64UrlEncoder
 */
class Base64UrlEncoderTest extends TestCase
{
    /**
     * @test
     */
    public function canBase64UrlEncode(): void
    {
        $sut = new Base64UrlEncoder();
        $expected = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9';
        $data = json_encode([
            'alg' => 'RS256',
            'typ' => 'JWT',
        ]);
        $actual = $sut->encode($data);
        $this->assertSame($expected, $actual);
    }

    /**
     * @test
     */
    public function canBase64UrlEncodeJoseHeaderData(): void
    {
        $sut = new Base64UrlEncoder();
        $expected = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9';
        $header = new PhpJwt\JoseHeader([
            'alg' => 'RS256',
            'typ' => 'JWT',
        ]);
        $data = $header->getJson();
        $actual = $sut->encode($data);
        $this->assertSame($expected, $actual);
    }
}
