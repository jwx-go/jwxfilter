// Package openidfilter provides filters for [openid.Token] claims.
//
// The OpenID Connect Core 1.0 claim list is larger than RFC 7519, so
// the standard filter here supersedes [jwtfilter.Standard].
//
// # Two flavors
//
// Each constructor comes in two flavors:
//
//   - [ByName] / [Standard] return [jwxfilter.Filter][jwt.Token]. The
//     input/output type is [jwt.Token] because the underlying generic
//     filter requires Clone() (T, error) and [openid.Token]'s Clone
//     method returns [jwt.Token]. An [openid.Token] satisfies
//     [jwt.Token] via interface embedding and can be passed in
//     directly; the result is typed as [jwt.Token] and the caller
//     type-asserts back to [openid.Token] to reach OpenID-specific
//     accessors.
//
//   - [ByNameTyped] / [StandardTyped] return
//     [jwxfilter.Filter][openid.Token]. They wrap the corresponding
//     jwt-typed filter and assert the result back, so the call site
//     never sees a [jwt.Token]. The assertion is safe in practice
//     because [openid.Token] implementations Clone to a concrete type
//     that satisfies both interfaces.
//
// Reach for the typed constructors when the call site is OpenID-only
// and the caller would otherwise type-assert; reach for the untyped
// constructors when filtering a heterogeneous stream of [jwt.Token]
// values.
package openidfilter

import (
	"fmt"

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

// ByName returns a filter that keeps (via Filter) or drops (via Reject) the
// named claims. The filter accepts any [jwt.Token], including [openid.Token].
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

// ByNameTyped is the [openid.Token]-typed counterpart to [ByName].
// Filter and Reject accept and return [openid.Token] directly, so
// callers do not need to type-assert the result before reaching for
// OpenID-specific accessors. Internally the call delegates to a
// [ByName] filter and asserts the [jwt.Token] result back to
// [openid.Token].
//
// The assertion succeeds whenever the input value's Clone returns
// the same concrete type that satisfies [openid.Token]; the standard
// [openid.Token] implementation does. If a custom implementation
// returns a value that does not satisfy [openid.Token], Filter /
// Reject return an error rather than panic.
func ByNameTyped(names ...string) jwxfilter.Filter[openid.Token] {
	return openidTypedFilter{inner: ByName(names...)}
}

// StandardTyped is the [openid.Token]-typed counterpart to [Standard].
// See [ByNameTyped] for the assertion contract.
func StandardTyped() jwxfilter.Filter[openid.Token] {
	return openidTypedFilter{inner: Standard()}
}

// openidTypedFilter wraps a [jwxfilter.Filter][jwt.Token] and surfaces
// it as [jwxfilter.Filter][openid.Token]. See [ByNameTyped] for the
// design rationale.
type openidTypedFilter struct {
	inner jwxfilter.Filter[jwt.Token]
}

func (f openidTypedFilter) Filter(t openid.Token) (openid.Token, error) {
	return assertOpenID(f.inner.Filter(t))
}

func (f openidTypedFilter) Reject(t openid.Token) (openid.Token, error) {
	return assertOpenID(f.inner.Reject(t))
}

func assertOpenID(out jwt.Token, err error) (openid.Token, error) {
	if err != nil {
		return nil, err
	}
	typed, ok := out.(openid.Token)
	if !ok {
		return nil, fmt.Errorf(`openidfilter: filter returned %T, expected an openid.Token implementation`, out)
	}
	return typed, nil
}
