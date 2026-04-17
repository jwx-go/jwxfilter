// Package jwsfilter provides filters for [jws.Headers] fields.
//
// EXPERIMENTAL: Every exported symbol in this package is experimental and
// may change or be removed in any release.
package jwsfilter

import (
	"github.com/jwx-go/jwxfilter/v4"
	"github.com/jwx-go/jwxfilter/v4/internal/filterable"
	"github.com/lestrrat-go/jwx/v4/jws"
)

// standardHeaderNames enumerates the eleven header parameters defined by
// RFC 7515 (alg, cty, crit, jwk, jku, kid, typ, x5c, x5t, x5t#S256, x5u).
var standardHeaderNames = []string{
	jws.AlgorithmKey,
	jws.ContentTypeKey,
	jws.CriticalKey,
	jws.JWKKey,
	jws.JWKSetURLKey,
	jws.KeyIDKey,
	jws.TypeKey,
	jws.X509CertChainKey,
	jws.X509CertThumbprintKey,
	jws.X509CertThumbprintS256Key,
	jws.X509URLKey,
}

// ByName returns a filter that keeps (via Filter) or drops (via Reject) the
// named fields from a [jws.Headers].
//
// EXPERIMENTAL: This API may change or be removed in any release.
func ByName(names ...string) jwxfilter.Filter[jws.Headers] {
	return filterable.NewNameBased[jws.Headers](names...)
}

// Standard returns a filter targeting the eleven RFC 7515 standard header
// parameters. Use Filter to keep only standard fields, or Reject to keep only
// custom fields.
//
// EXPERIMENTAL: This API may change or be removed in any release.
func Standard() jwxfilter.Filter[jws.Headers] {
	return ByName(standardHeaderNames...)
}
