<?php

declare(strict_types=1);

namespace PhpJwt;

use stdClass;

class JoseHeader
{
    public function __construct(private array $parameters)
    {
        $this->validate();
    }

    private function validate(): void
    {
        if (! array_key_exists('alg', $this->parameters)) {
            throw new Exception('required property "alg" not set');
        }

        if (array_key_exists('cty', $this->parameters) && $this->parameters['cty'] !== 'JWT') {
            throw new Exception('value for property "cty" must be "JWT"');
        }
    }

    public function getAlg(): string
    {
        return $this->parameters['alg'];
    }

    public function getJson(): string
    {
        $object = new stdClass();
        foreach ($this->parameters as $key => $value) {
            if ($this->isValidProperty($key)) {
                $object->$key = $value;
            }
        }
        $object->typ = 'JWT';
        return json_encode($object, JSON_THROW_ON_ERROR);
    }

    private function isValidProperty($key): bool
    {
        return in_array($key, [
            'alg',
            'aud',
            'cty',
            'iss',
            'sub',
            'typ',
        ]);
    }
}
