// Package jwxfilter provides optional filter and introspection helpers for
// github.com/lestrrat-go/jwx/v4. It is imported separately from core so that
// applications that do not need filtering pay no cost for it.
//
// The public surface is intentionally small: one generic interface Filter[T],
// one Mappable interface, and the AsMap helper. All framework machinery lives
// inside an internal package. Users construct filters via the per-JOSE-type
// subpackages (jwtfilter, jwsfilter, jwefilter, jwkfilter, openidfilter).
package jwxfilter

// Filter is a filter over any JWx object type. The two methods are
// complementary set operations on the configured field-name set N
// against the input object's fields:
//
//   - Filter(obj) returns a new object containing ONLY the fields whose
//     names are in N. Every other field is REMOVED.
//   - Reject(obj) returns a new object with the fields whose names are
//     in N REMOVED. Every other field is KEPT.
//
// English shorthand is the easy way to invert this. "Filter out the
// password claim" reads as "remove the password claim" — but in this
// API, that is what Reject does, not what Filter does. Read each call
// site as keep-only-N (Filter) or drop-N (Reject).
//
// The footgun this prevents:
//
//	// WRONG — produces a token containing ONLY "password" and "secret_q",
//	// dropping every other claim. If this is then logged or returned to a
//	// client, the secrets land somewhere they should not.
//	leaky, _ := jwtfilter.ByName("password", "secret_q").Filter(token)
//
//	// RIGHT — produces a token with "password" and "secret_q" REMOVED,
//	// keeping every other claim.
//	safe, _ := jwtfilter.ByName("password", "secret_q").Reject(token)
//
// Users obtain a Filter by calling one of the constructors in the
// per-JOSE-type subpackages:
//   - jwtfilter.ByName / jwtfilter.Standard (for jwt.Token)
//   - jwsfilter.ByName / jwsfilter.Standard (for jws.Headers)
//   - jwefilter.ByName / jwefilter.Standard (for jwe.Headers)
//   - jwkfilter.ByName / jwkfilter.RSAStandard / etc. (for jwk.Key)
type Filter[T any] interface {
	// Filter returns a new T containing ONLY the fields whose names
	// match the filter's configured set. All other fields are removed.
	Filter(obj T) (T, error)
	// Reject returns a new T with the fields whose names match the
	// filter's configured set REMOVED. All other fields are kept.
	Reject(obj T) (T, error)
}
