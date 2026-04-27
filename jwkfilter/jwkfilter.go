// Package jwkfilter provides filters for [jwk.Key] fields.
package jwkfilter

import (
	"github.com/jwx-go/jwxfilter/v4"
	"github.com/jwx-go/jwxfilter/v4/internal/filterable"
	"github.com/lestrrat-go/jwx/v4/jwk"
)

// commonKeyFields lists the RFC 7517 fields present on every JWK
// regardless of key type.
var commonKeyFields = []string{
	jwk.KeyTypeKey,
	jwk.KeyUsageKey,
	jwk.KeyOpsKey,
	jwk.AlgorithmKey,
	jwk.KeyIDKey,
	jwk.X509URLKey,
	jwk.X509CertChainKey,
	jwk.X509CertThumbprintKey,
	jwk.X509CertThumbprintS256Key,
}

// ByName returns a filter that keeps (via Filter) or drops (via Reject) the
// named fields from a [jwk.Key].
func ByName(names ...string) jwxfilter.Filter[jwk.Key] {
	return filterable.NewNameBased[jwk.Key](names...)
}

// RSAStandard returns a filter for RFC 7517 + RFC 7518 RSA key fields
// (kty, use, key_ops, alg, kid, x5u, x5c, x5t, x5t#S256, e, n, d, dp, dq,
// p, q, qi).
func RSAStandard() jwxfilter.Filter[jwk.Key] {
	names := append([]string{}, commonKeyFields...)
	names = append(names,
		jwk.RSAEKey, jwk.RSANKey,
		jwk.RSADKey, jwk.RSADPKey, jwk.RSADQKey,
		jwk.RSAPKey, jwk.RSAQKey, jwk.RSAQIKey,
	)
	return ByName(names...)
}

// ECDSAStandard returns a filter for RFC 7517 + RFC 7518 ECDSA key fields
// (kty, use, key_ops, alg, kid, x5u, x5c, x5t, x5t#S256, crv, x, y, d).
func ECDSAStandard() jwxfilter.Filter[jwk.Key] {
	names := append([]string{}, commonKeyFields...)
	names = append(names,
		jwk.ECDSACrvKey, jwk.ECDSAXKey, jwk.ECDSAYKey, jwk.ECDSADKey,
	)
	return ByName(names...)
}

// OKPStandard returns a filter for RFC 8037 OKP key fields
// (kty, use, key_ops, alg, kid, x5u, x5c, x5t, x5t#S256, crv, x, d).
func OKPStandard() jwxfilter.Filter[jwk.Key] {
	names := append([]string{}, commonKeyFields...)
	names = append(names, jwk.OKPCrvKey, jwk.OKPXKey, jwk.OKPDKey)
	return ByName(names...)
}

// SymmetricStandard returns a filter for RFC 7517 symmetric key fields
// (kty, use, key_ops, alg, kid, x5u, x5c, x5t, x5t#S256, k).
func SymmetricStandard() jwxfilter.Filter[jwk.Key] {
	names := append([]string{}, commonKeyFields...)
	names = append(names, jwk.SymmetricOctetsKey)
	return ByName(names...)
}

// AKPStandard returns a filter for AKP key fields
// (kty, use, key_ops, alg, kid, x5u, x5c, x5t, x5t#S256, pub, priv).
func AKPStandard() jwxfilter.Filter[jwk.Key] {
	names := append([]string{}, commonKeyFields...)
	names = append(names, jwk.AKPPubKey, jwk.AKPPrivKey)
	return ByName(names...)
}
