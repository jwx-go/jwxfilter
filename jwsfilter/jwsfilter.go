// Package jwsfilter provides filters for [jws.Headers] fields.
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

// ByName returns a filter over the given header names. Filter keeps
// ONLY the named headers (drops everything else); Reject drops the
// named headers (keeps everything else). See the [jwxfilter.Filter]
// godoc for the keep-only/drop inversion footgun.
func ByName(names ...string) jwxfilter.Filter[jws.Headers] {
	return filterable.NewNameBased[jws.Headers](names...)
}

// Standard returns a filter targeting the eleven RFC 7515 standard header
// parameters. Use Filter to keep only standard fields, or Reject to keep only
// custom fields.
func Standard() jwxfilter.Filter[jws.Headers] {
	return ByName(standardHeaderNames...)
}
