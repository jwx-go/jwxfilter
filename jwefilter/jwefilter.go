// Package jwefilter provides filters for [jwe.Headers] fields.
//
// EXPERIMENTAL: Every exported symbol in this package is experimental and
// may change or be removed in any release.
package jwefilter

import (
	"github.com/jwx-go/jwxfilter/v4"
	"github.com/jwx-go/jwxfilter/v4/internal/filterable"
	"github.com/lestrrat-go/jwx/v4/jwe"
)

// standardHeaderNames enumerates the eighteen header parameters defined by
// RFC 7516 (apu, apv, alg, zip, enc, cty, crit, ek, epk, jwk, jku, kid,
// psk_id, typ, x5c, x5t, x5t#S256, x5u).
var standardHeaderNames = []string{
	jwe.AgreementPartyUInfoKey,
	jwe.AgreementPartyVInfoKey,
	jwe.AlgorithmKey,
	jwe.CompressionKey,
	jwe.ContentEncryptionKey,
	jwe.ContentTypeKey,
	jwe.CriticalKey,
	jwe.EncapsulatedKeyKey,
	jwe.EphemeralPublicKeyKey,
	jwe.JWKKey,
	jwe.JWKSetURLKey,
	jwe.KeyIDKey,
	jwe.PSKIDKey,
	jwe.TypeKey,
	jwe.X509CertChainKey,
	jwe.X509CertThumbprintKey,
	jwe.X509CertThumbprintS256Key,
	jwe.X509URLKey,
}

// ByName returns a filter that keeps (via Filter) or drops (via Reject) the
// named fields from a [jwe.Headers].
//
// EXPERIMENTAL: This API may change or be removed in any release.
func ByName(names ...string) jwxfilter.Filter[jwe.Headers] {
	return filterable.NewNameBased[jwe.Headers](names...)
}

// Standard returns a filter targeting the eighteen RFC 7516 standard header
// parameters. Use Filter to keep only standard fields, or Reject to keep only
// custom fields.
//
// EXPERIMENTAL: This API may change or be removed in any release.
func Standard() jwxfilter.Filter[jwe.Headers] {
	return ByName(standardHeaderNames...)
}
