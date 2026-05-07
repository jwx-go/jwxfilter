// Package jwsfilter provides filters for [jws.Headers] fields.
//
// # Single-headers contract
//
// The filters returned by [ByName] and [Standard] operate on one
// [jws.Headers] value at a time. They do NOT traverse a [jws.Message].
//
// A general-form JWS-JSON message carries multiple header layers per
// signature: a protected header (integrity-protected, base64url-encoded
// on the wire), an unprotected header (sibling JSON object, mutable in
// transit), and the same pair repeated for every signer in a
// multi-signature message. Applying a filter to one layer leaves the
// others untouched. Concretely:
//
//	// Wrong: only strips jku from the protected header.
//	clean, _ := jwsfilter.ByName(jws.JWKSetURLKey).Reject(
//	    msg.Signatures()[0].ProtectedHeaders())
//	_ = msg.Signatures()[0].SetProtectedHeaders(clean)
//	// msg.Signatures()[0].PublicHeaders() — and every other
//	// signature's headers — still carry the original jku.
//
// To scrub a header parameter from every place it could appear in a
// [jws.Message], the caller iterates each [jws.Signature]'s
// ProtectedHeaders and PublicHeaders and applies the filter to each.
// Nothing in this package does that automatically; the design
// assumption is that callers know which layer they care about.
//
// # Security note
//
// Stripping a header parameter from one layer does not stop a verifier
// or downstream consumer that reads the OTHER layer from observing it.
// jwx's [jws.Verify] consults the protected layer for default key
// lookup, but custom [jws.KeyProvider] implementations or downstream
// policy code may inspect the unprotected layer too. If you rely on
// this package as part of an SSRF mitigation (e.g. removing jku before
// verification), apply the filter to every layer the downstream
// verifier might read — or use raw [jws.Message] mutation, which the
// caller already needs to do for non-protected layers.
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
func ByName(names ...string) jwxfilter.Filter[jws.Headers] {
	return filterable.NewNameBased[jws.Headers](names...)
}

// Standard returns a filter targeting the eleven RFC 7515 standard header
// parameters. Use Filter to keep only standard fields, or Reject to keep only
// custom fields.
func Standard() jwxfilter.Filter[jws.Headers] {
	return ByName(standardHeaderNames...)
}
