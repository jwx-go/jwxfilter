package openidfilter_test

import (
	"testing"

	"github.com/jwx-go/jwxfilter/v4/openidfilter"
	"github.com/lestrrat-go/jwx/v4/jwt/openid"
	"github.com/stretchr/testify/require"
)

func makeOpenIDToken(t *testing.T) openid.Token {
	t.Helper()
	tok := openid.New()
	require.NoError(t, tok.Set(openid.SubjectKey, "alice@example.com"))
	require.NoError(t, tok.Set(openid.NameKey, "Alice"))
	require.NoError(t, tok.Set(openid.EmailKey, "alice@example.com"))
	require.NoError(t, tok.Set("custom_claim", "private-value"))
	return tok
}

// TestByNameTypedReturnsOpenIDToken pins the contract of the typed
// wrapper: ByNameTyped's Filter and Reject return openid.Token
// directly so the caller can reach OpenID-specific accessors
// without a type assertion.
func TestByNameTypedReturnsOpenIDToken(t *testing.T) {
	t.Run("Filter keeps named claim and returns openid.Token", func(t *testing.T) {
		src := makeOpenIDToken(t)

		filtered, err := openidfilter.ByNameTyped(openid.NameKey).Filter(src)
		require.NoError(t, err)
		// No type assertion: filtered is already openid.Token.
		got, ok := filtered.Name()
		require.True(t, ok, "name claim must survive Filter")
		require.Equal(t, "Alice", got)
	})

	t.Run("Reject drops named claim and returns openid.Token", func(t *testing.T) {
		src := makeOpenIDToken(t)

		rejected, err := openidfilter.ByNameTyped(openid.NameKey).Reject(src)
		require.NoError(t, err)
		_, ok := rejected.Name()
		require.False(t, ok, "name claim must be dropped by Reject")
		// Other claims are preserved.
		email, ok := rejected.Email()
		require.True(t, ok)
		require.Equal(t, "alice@example.com", email)
	})
}

// TestStandardTypedDropsCustomClaims pins that the typed Standard
// filter behaves like the untyped one — keeping only RFC 7519 +
// OpenID Core claims — and that the result is openid.Token typed.
func TestStandardTypedDropsCustomClaims(t *testing.T) {
	src := makeOpenIDToken(t)

	t.Run("Filter keeps standard, drops custom", func(t *testing.T) {
		filtered, err := openidfilter.StandardTyped().Filter(src)
		require.NoError(t, err)
		require.True(t, filtered.Has(openid.SubjectKey))
		require.True(t, filtered.Has(openid.EmailKey))
		require.False(t, filtered.Has("custom_claim"))
	})

	t.Run("Reject keeps custom only", func(t *testing.T) {
		rejected, err := openidfilter.StandardTyped().Reject(src)
		require.NoError(t, err)
		require.False(t, rejected.Has(openid.SubjectKey))
		require.True(t, rejected.Has("custom_claim"))
	})
}
