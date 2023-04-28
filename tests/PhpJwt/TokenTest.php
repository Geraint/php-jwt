<?php

declare(strict_types=1);

namespace PhpJwt;

use PHPUnit\Framework\TestCase;

class TokenTest extends TestCase
{
    /**
     * @test
     * @doesNotPerformAssertions
     */
    public function canBeInstantiated(): void
    {
        $sut = new Token();
    }
}
