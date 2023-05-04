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
    public function throwsExceptionIfPublicAndPrivateKeysAreNotProvided(array $parameters): void
    {
        // TODO do I need the public key to sign the token?
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
}
