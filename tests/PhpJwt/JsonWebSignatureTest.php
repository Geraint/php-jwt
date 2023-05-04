<?php

declare(strict_types=1);

namespace PhpJwt;

use PHPUnit\Framework\TestCase;
use PhpJwt\Encoder;

/**
 * @covers \PhpJwt\JsonWebSignature
 */
class JsonWebSignatureTest extends TestCase
{
    /**
     * @test
     */
    public function canSignTokenWithHmacAlgorithms(): void
    {
        $alg = 'HS256'; // could be any support algorithm
        $header = new JoseHeader([
            'typ' => 'JWT',
            'alg' => $alg,
        ]);
        $claims = new JwtClaimsSet([
            'sub'  => '1234567890',
            'name' => 'Joe Bloggs',
            'iat'  => 1516239022,
        ]);
        $parameters = [
            'secret' => 'could just as easily be a public/private key pair',
        ];

        $encoder = $this->createMock(Encoder\AbstractEncoder::class);
        $encoder
            ->expects($this->once())
            ->method('getSignedToken')
            ->with($header, $claims, $parameters);

        $encoderFactory = $this->createMock(Encoder\EncoderFactory::class);
        $encoderFactory
            ->expects($this->once())
            ->method('createEncoder')
            ->with($alg)
            ->willReturn($encoder);

        $sut = new JsonWebSignature($encoderFactory);
        $sut->getSignedToken($header, $claims, $parameters);
    }
}
