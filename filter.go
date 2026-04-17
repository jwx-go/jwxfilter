// Package jwxfilter provides optional filter and introspection helpers for
// github.com/lestrrat-go/jwx/v4. It is imported separately from core so that
// applications that do not need filtering pay no cost for it.
//
// The public surface is intentionally small: one generic interface Filter[T],
// one Mappable interface, and the AsMap helper. All framework machinery lives
// inside an internal package. Users construct filters via the per-JOSE-type
// subpackages (jwtfilter, jwsfilter, jwefilter, jwkfilter).
//
// EVERY exported symbol in this package and its subpackages is EXPERIMENTAL
// and may change or be removed in any release. The module does not provide
// semver compatibility guarantees.
package jwxfilter

// Filter is a filter over any JWx object type.
//
// Filter returns a new object containing only the fields that match the
// filter's criteria. Reject returns a new object containing only the fields
// that do NOT match.
//
// Users obtain a Filter by calling one of the constructors in the
// per-JOSE-type subpackages:
//   - jwtfilter.ByName / jwtfilter.Standard (for jwt.Token)
//   - jwsfilter.ByName / jwsfilter.Standard (for jws.Headers)
//   - jwefilter.ByName / jwefilter.Standard (for jwe.Headers)
//   - jwkfilter.ByName / jwkfilter.RSAStandard / etc. (for jwk.Key)
//
// EXPERIMENTAL: This API may change or be removed in any release.
type Filter[T any] interface {
	Filter(obj T) (T, error)
	Reject(obj T) (T, error)
}
