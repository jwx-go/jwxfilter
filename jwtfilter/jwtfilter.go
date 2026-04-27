// Package jwtfilter provides filters for [jwt.Token] claims.
package jwtfilter

import (
	"github.com/jwx-go/jwxfilter/v4"
	"github.com/jwx-go/jwxfilter/v4/internal/filterable"
	"github.com/lestrrat-go/jwx/v4/jwt"
)

// standardClaimNames enumerates the seven claims defined by RFC 7519.
// Mirrors jwt.stdClaimNames from core; kept in lock-step in the rare event
// the set changes.
var standardClaimNames = []string{
	jwt.AudienceKey,
	jwt.ExpirationKey,
	jwt.IssuedAtKey,
	jwt.IssuerKey,
	jwt.JwtIDKey,
	jwt.NotBeforeKey,
	jwt.SubjectKey,
}

// ByName returns a filter over the given claim names. Filter keeps
// ONLY the named claims (drops everything else); Reject drops the
// named claims (keeps everything else). To strip sensitive claims —
// e.g. "password", "secret_q" — call Reject, not Filter; see the
// [jwxfilter.Filter] godoc for the keep-only/drop inversion footgun.
func ByName(names ...string) jwxfilter.Filter[jwt.Token] {
	return filterable.NewNameBased[jwt.Token](names...)
}

// Standard returns a filter targeting the seven RFC 7519 standard claims
// (aud, exp, iat, iss, jti, nbf, sub). Use Filter to keep only standard
// claims, or Reject to keep only custom claims.
func Standard() jwxfilter.Filter[jwt.Token] {
	return ByName(standardClaimNames...)
}
