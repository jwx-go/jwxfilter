// Package jwefilter provides filters for [jwe.Headers] fields.
//
// # Single-headers contract
//
// The filters returned by [ByName] and [Standard] operate on one
// [jwe.Headers] value at a time. They do NOT traverse a [jwe.Message].
//
// A general-form JWE-JSON message carries multiple header layers: a
// protected header (integrity-protected via the AEAD AAD), an
// unprotected header (sibling JSON object, mutable in transit), and a
// per-recipient header on each [jwe.Recipient]. Applying a filter to
// one layer leaves the others untouched. Concretely:
//
//	// Wrong: only strips jku from the protected header.
//	clean, _ := jwefilter.ByName(jwe.JWKSetURLKey).Reject(
//	    msg.ProtectedHeaders())
//	_ = msg.SetProtectedHeaders(clean)
//	// msg.UnprotectedHeaders() — and every msg.Recipients()[i].Headers() —
//	// still carry the original jku.
//
// To scrub a header parameter from every place it could appear in a
// [jwe.Message], the caller applies the filter to ProtectedHeaders,
// UnprotectedHeaders, and the Headers of every Recipient. Nothing in
// this package does that automatically; the design assumption is that
// callers know which layer they care about.
//
// # Security note
//
// Stripping a header parameter from one layer does not stop a
// decrypter or downstream consumer that reads the OTHER layer from
// observing it. jwx's [jwe.Decrypt] consults the protected layer for
// default key selection, but custom key-provider extensions or
// downstream policy code may inspect the unprotected and per-
// recipient layers too. If you rely on this package as part of an
// SSRF mitigation (e.g. removing jku before decryption), apply the
// filter to every layer the downstream decrypter might read — or use
// raw [jwe.Message] mutation, which the caller already needs to do
// for non-protected layers.
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
func ByName(names ...string) jwxfilter.Filter[jwe.Headers] {
	return filterable.NewNameBased[jwe.Headers](names...)
}

// Standard returns a filter targeting the eighteen RFC 7516 standard header
// parameters. Use Filter to keep only standard fields, or Reject to keep only
// custom fields.
func Standard() jwxfilter.Filter[jwe.Headers] {
	return ByName(standardHeaderNames...)
}
