# jwxfilter companion

## Purpose

Optional filter + introspection helpers extracted from `github.com/lestrrat-go/jwx/v4` core in v4. Core's JOSE operations do not depend on this module; users opt in via import.

## Layout

```
jwxfilter/
├── filter.go          # public Filter[T] + unexported machinery
├── map.go             # public Mappable + AsMap
├── jwtfilter/         # filters for jwt.Token
├── jwsfilter/         # filters for jws.Headers
├── jwefilter/         # filters for jwe.Headers
└── jwkfilter/         # filters for jwk.Key
```

The root package exposes only:
- `Filter[T any]` — one generic interface (`Filter(T) (T, error)` + `Reject(T) (T, error)`)
- `Mappable` interface + `AsMap(m Mappable, dst map[string]any) error`

Everything else (`filterLogic`, `nameBasedFilter[T]`, `apply`, `reject`, `filterable[T]`, `newNameBasedFilter`, `filterLogicFunc`) is unexported. Users never construct custom filter logic — they use the per-JOSE-type subpackages.

## Per-type subpackages

Each subpackage exposes a `ByName(names ...string)` constructor and one or more `Standard*()` convenience constructors that return `jwxfilter.Filter[T]` for the appropriate JOSE type.

Standard field-name lists are hardcoded using core's already-exported constants (e.g. `jwt.AudienceKey`, `jws.AlgorithmKey`, `jwk.RSAEKey`). RFC-standard claim/header/field sets are effectively frozen; drift risk is small.

## Build / Test

Requires `GOEXPERIMENT=jsonv2` (jwx v4 dependency):

```sh
GOEXPERIMENT=jsonv2 go test ./...
```

## Branch Policy

| Branch | Purpose |
|--------|---------|
| `v*` (e.g. `v4`) | Release tags only. NEVER commit directly. |
| `develop/v*` | Active development. All feature branches merge here. |
| Feature branches | Branch from `develop/v*`, merge via PR. |
