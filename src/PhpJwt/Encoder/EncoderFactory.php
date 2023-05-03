<?php

declare(strict_types=1);

namespace PhpJwt\Encoder;

class EncoderFactory
{
    public function createEncoder(string $algorithm): AbstractEncoder
    {
        return new HmacEncoder($algorithm);
    }
}
