<?php

declare(strict_types=1);

namespace PhpJwt\Encoder;

use PHPUnit\Framework\TestCase;

/**
 * @covers \PhpJwt\Encoder\EncoderFactory
 */
class EncoderFactoryTest extends TestCase
{
    /**
     * @test
     * @dataProvider createEncoderDataProvider
     */
    public function canCreateEncoders(string $algorithm, string $expected): void
    {
        $factory = new EncoderFactory();
        $actual = $factory->createEncoder($algorithm);
        $this->assertInstanceOf($expected, $actual);
    }

    public static function createEncoderDataProvider(): array
    {
        return [
            'HS256' => [
                'algorithm' => 'HS256',
                'expected'  => HmacEncoder::class
            ],
        ];
    }
}
