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

    public function getJson(): string
    {
        $object = new stdClass();
        $object->typ = 'JWT';
        $object->alg = $this->parameters['alg'];
        foreach ([
            'cty',
            'iss',
            'sub',
            'aud',
        ] as $key) {
            $object = $this->maybeAddParameter($key, $object);
        }
        return json_encode($object, JSON_THROW_ON_ERROR);
    }

    private function maybeAddParameter(string $key, stdClass $object): stdClass
    {
        if (array_key_exists($key, $this->parameters)) {
            $object->$key = $this->parameters[$key];
        }
        return $object;
    }
}
