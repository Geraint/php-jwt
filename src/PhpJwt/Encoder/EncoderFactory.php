<?php

declare(strict_types=1);

namespace PhpJwt\Encoder;

class EncoderFactory
{
    public function createEncoder(string $algorithm): AbstractEncoder
    {
        if (str_starts_with($algorithm, 'HS')) {
            return new HmacEncoder($algorithm);
        }
        
        if (str_starts_with($algorithm, 'RS')) {
            return new RsassaPkcs1V15Encoder($algorithm);
        }
    }
}
