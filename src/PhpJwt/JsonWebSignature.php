<?php

declare(strict_types=1);

namespace PhpJwt;

use PhpJwt\Encoder;

class JsonWebSignature
{
    public function __construct(private Encoder\EncoderFactory $encoderFactory)
    {
    }

    public function getSignedToken(JoseHeader $header, JwtClaimsSet $claims, $parameters): string
    {
        $encoder = $this->encoderFactory->createEncoder($header->getAlg());
        return $encoder->getSignedToken($header, $claims, $parameters);
    }
}
