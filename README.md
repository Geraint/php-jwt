# PHP JWT

![Build Status](https://github.com/Geraint/php-jwt/actions/workflows/build-and-test.yml/badge.svg)

This is a test implementation of JWT's in PHP,
which I've built to help me learn how JWT's work.

It is not recommended for Production use.
Use at your own risk.

## Supported algorithms

- HS256
- HS384
- HS512
- RS256
- RS384
- RS512

## Usage

### Encoding

To make a signed token, you can do the following:

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

This will display:

```
string(157) "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvZSBCbG9nZ3MiLCJpYXQiOjE1MTYyMzkwMjJ9.cWPf6g4AMgzx5CorjSp8bK1ywXIW5o2dM7bBdUMHhlw"
```

The RS256, RS384, and RS512 algorithms are supported.

When using these algorithms,
`parameters` should contain a `private_key`, rather than a `secret`.

The private key is a string containing the key itself, and _not_ a file path or similar.

### Verification

To verify a received token, you can do the following:

```php
<?php

use PhpJwt\Jwt;

$token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvZSBCbG9nZ3MiLCJpYXQiOjE1MTYyMzkwMjJ9.cWPf6g4AMgzx5CorjSp8bK1ywXIW5o2dM7bBdUMHhlw';

$isVerified = Jwt::verify(
    token: $token,
    parameters: [
        'secret' => 'my top secret',
    ],
);

var_dump($isVerified);
```

This will display:

```
bool(true)
```

When using RS256, RS384 or RS512, `parameters` should contain a `public_key`, rather than a `secret`.

As with `private_key`'s above, the `public_key` is a string containing the key itself, and _not_ a file path or similar.
