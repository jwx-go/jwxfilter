// Package openidfilter provides filters for [openid.Token] claims.
//
// The OpenID Connect Core 1.0 claim list is larger than RFC 7519, so the
// standard filter here supersedes [jwtfilter.Standard]. The filters
// operate on and return [jwt.Token] because that is what [openid.Token]'s
// Clone method returns — [openid.Token] embeds [jwt.Token] and can be
// passed directly.
package openidfilter

import (
	"github.com/jwx-go/jwxfilter/v4"
	"github.com/jwx-go/jwxfilter/v4/internal/filterable"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/lestrrat-go/jwx/v4/jwt/openid"
)

// standardClaimNames enumerates the 26 standard OpenID Connect Core 1.0
// claims (a superset of the seven RFC 7519 claims).
var standardClaimNames = []string{
	openid.AddressKey,
	openid.AudienceKey,
	openid.BirthdateKey,
	openid.EmailKey,
	openid.EmailVerifiedKey,
	openid.ExpirationKey,
	openid.FamilyNameKey,
	openid.GenderKey,
	openid.GivenNameKey,
	openid.IssuedAtKey,
	openid.IssuerKey,
	openid.JwtIDKey,
	openid.LocaleKey,
	openid.MiddleNameKey,
	openid.NameKey,
	openid.NicknameKey,
	openid.NotBeforeKey,
	openid.PhoneNumberKey,
	openid.PhoneNumberVerifiedKey,
	openid.PictureKey,
	openid.PreferredUsernameKey,
	openid.ProfileKey,
	openid.SubjectKey,
	openid.UpdatedAtKey,
	openid.WebsiteKey,
	openid.ZoneinfoKey,
}

// ByName returns a filter over the given claim names. Filter keeps
// ONLY the named claims (drops everything else); Reject drops the
// named claims (keeps everything else). To strip sensitive claims,
// call Reject, not Filter; see the [jwxfilter.Filter] godoc for the
// keep-only/drop inversion footgun. The filter accepts any
// [jwt.Token], including [openid.Token].
func ByName(names ...string) jwxfilter.Filter[jwt.Token] {
	return filterable.NewNameBased[jwt.Token](names...)
}

// Standard returns a filter targeting the 26 OpenID Connect Core 1.0
// standard claims. Use Filter to keep only standard claims, or Reject to
// keep only custom claims.
//
// Pass an [openid.Token] to exercise OpenID-specific claim names; plain
// [jwt.Token] values work too but will only carry claims already on them.
func Standard() jwxfilter.Filter[jwt.Token] {
	return ByName(standardClaimNames...)
}
