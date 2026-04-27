// Package jwxfilter provides optional filter and introspection helpers for
// github.com/lestrrat-go/jwx/v4. It is imported separately from core so that
// applications that do not need filtering pay no cost for it.
//
// The public surface is intentionally small: one generic interface Filter[T],
// one Mappable interface, and the AsMap helper. All framework machinery lives
// inside an internal package. Users construct filters via the per-JOSE-type
// subpackages (jwtfilter, jwsfilter, jwefilter, jwkfilter, openidfilter).
//
// # Filters are post-validation
//
// Apply filters AFTER signature verification, claim validation, and key
// import — never before. Filters drop fields, and running validation on a
// filtered object can cause required-claim, audience, issuer, or other
// downstream checks to silently pass against an input that no longer
// contains those claims. The intended pattern is:
//
//	tok, err := jwt.Parse(raw, jwt.WithKey(...))      // verify + validate
//	if err != nil { return err }
//	stripped, err := jwtfilter.Standard().Filter(tok) // then filter
//
// not the other way around.
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
// Users obtain a Filter by calling one of the constructors in the
// per-JOSE-type subpackages:
//   - jwtfilter.ByName / jwtfilter.Standard (for jwt.Token)
//   - jwsfilter.ByName / jwsfilter.Standard (for jws.Headers)
//   - jwefilter.ByName / jwefilter.Standard (for jwe.Headers)
//   - jwkfilter.ByName / jwkfilter.RSAStandard / etc. (for jwk.Key)
type Filter[T any] interface {
	Filter(obj T) (T, error)
	Reject(obj T) (T, error)
}
