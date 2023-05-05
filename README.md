# PHP JWT

This is a test implementation of JWT's in PHP, which I've built to help me learn how JWT's work.

It is not recommended for Production use.

![Build Status](https://github.com/Geraint/php-jwt/actions/workflows/build-and-test.yml/badge.svg)

## Usage

```php
<?php

use PhpJwt\Jwt;

$jwt = Jwt::encode(
    header: [
        'alg'    => 'HS256',
        'typ'    => 'JWT',
    ],
    payload: [
        'sub'    => '1234567890',
        'name'   => 'Joe Bloggs',
        'iat'    => 1516239022,
    ],
    parameters: [
        'secret' => 'my top secret',
    ]
);

var_dump($jwt);
```

... will display:

```
string(157) "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvZSBCbG9nZ3MiLCJpYXQiOjE1MTYyMzkwMjJ9.cWPf6g4AMgzx5CorjSp8bK1ywXIW5o2dM7bBdUMHhlw"
```

The RS256 algorithm is supported, in which case `parameters` should contain a `private_key`, rather than a `secret`.

The private key is a string containing the key itself, and _not_ a file path or similar.
