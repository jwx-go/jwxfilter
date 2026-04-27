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
| `jwxfilter/openidfilter` | Filters for `openid.Token` (OpenID Connect Core 1.0 claims) |

## When to use

Apply filters **after** signature verification, claim validation, and key import — never before. Filters drop fields. If you filter first and then validate, downstream checks (required-claim, audience, issuer, custom validators) can silently pass against an input that no longer contains the claims they were configured to check.

```go
// Right: verify+validate, then filter
tok, err := jwt.Parse(raw, jwt.WithKey(...))
if err != nil { return err }
stripped, _ := jwtfilter.Standard().Filter(tok)

// Wrong: filter first, then validate against the stripped object
tok, _   := jwt.ParseInsecure(raw)
stripped, _ := jwtfilter.Standard().Filter(tok)
if err := jwt.Validate(stripped, jwt.WithRequiredClaim("app_role")); err != nil { ... }
// app_role was filtered out; the validator passes silently.
```

## Example

```go
import (
    "github.com/lestrrat-go/jwx/v4/jwt"
    "github.com/jwx-go/jwxfilter/v4/jwtfilter"
)

stripped, err := jwtfilter.Standard().Filter(token) // only RFC 7519 claims
custom,   err := jwtfilter.ByName("app_role").Filter(token)
```
