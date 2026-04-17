# jwxfilter

Optional filter and introspection helpers for [`github.com/lestrrat-go/jwx/v4`](https://github.com/lestrrat-go/jwx). This module was extracted from core in v4 — the JOSE operations (sign, verify, encrypt, decrypt, parse) in `jwx` do not depend on it.

## Install

```sh
go get github.com/jwx-go/jwxfilter/v4
```

## Layout

| Package | Use |
|---|---|
| `jwxfilter` | `Filter[T any]` interface, `Mappable` interface, `AsMap` helper |
| `jwxfilter/jwtfilter` | Filters for `jwt.Token` |
| `jwxfilter/jwsfilter` | Filters for `jws.Headers` |
| `jwxfilter/jwefilter` | Filters for `jwe.Headers` |
| `jwxfilter/jwkfilter` | Filters for `jwk.Key` |

## Example

```go
import (
    "github.com/lestrrat-go/jwx/v4/jwt"
    "github.com/jwx-go/jwxfilter/v4/jwtfilter"
)

stripped, err := jwtfilter.Standard().Filter(token) // only RFC 7519 claims
custom,   err := jwtfilter.ByName("app_role").Filter(token)
```

## Stability

Every exported symbol in this module carries an EXPERIMENTAL godoc marker. The API may change in any release until explicitly stabilized.
