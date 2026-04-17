package jwtfilter_test

import (
	"testing"
	"time"

	"github.com/jwx-go/jwxfilter/v4/jwtfilter"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/require"
)

const aLongLongTimeAgo = 233431200

func TestClaimNames(t *testing.T) {
	t.Run("ByName returns non-nil filter", func(t *testing.T) {
		cn := jwtfilter.ByName("a", "b", "c")
		require.NotNil(t, cn, "ByName should return a non-nil filter")
	})

	t.Run("Filter", func(t *testing.T) {
		cn := jwtfilter.ByName("a", "b", "c")

		token := jwt.New()
		require.NoError(t, token.Set("a", "value_a"), "token.Set should succeed")
		require.NoError(t, token.Set("b", "value_b"), "token.Set should succeed")
		require.NoError(t, token.Set("c", "value_c"), "token.Set should succeed")
		require.NoError(t, token.Set("d", "value_d"), "token.Set should succeed")
		require.NoError(t, token.Set("e", "value_e"), "token.Set should succeed")

		filtered, err := cn.Filter(token)
		require.NoError(t, err, "cn.Filter should succeed")

		require.True(t, filtered.Has("a"), "filtered token should have claim 'a'")
		require.True(t, filtered.Has("b"), "filtered token should have claim 'b'")
		require.True(t, filtered.Has("c"), "filtered token should have claim 'c'")
		require.False(t, filtered.Has("d"), "filtered token should not have claim 'd'")
		require.False(t, filtered.Has("e"), "filtered token should not have claim 'e'")

		val, ok := filtered.Field("a")
		require.True(t, ok, "filtered.Field should succeed")
		require.Equal(t, "value_a", val, "value for claim 'a' should be preserved")
	})

	t.Run("Reject", func(t *testing.T) {
		cn := jwtfilter.ByName("a", "b", "c")

		token := jwt.New()
		require.NoError(t, token.Set("a", "value_a"), "token.Set should succeed")
		require.NoError(t, token.Set("b", "value_b"), "token.Set should succeed")
		require.NoError(t, token.Set("c", "value_c"), "token.Set should succeed")
		require.NoError(t, token.Set("d", "value_d"), "token.Set should succeed")
		require.NoError(t, token.Set("e", "value_e"), "token.Set should succeed")

		rejected, err := cn.Reject(token)
		require.NoError(t, err, "cn.Reject should succeed")

		require.False(t, rejected.Has("a"), "rejected token should not have claim 'a'")
		require.False(t, rejected.Has("b"), "rejected token should not have claim 'b'")
		require.False(t, rejected.Has("c"), "rejected token should not have claim 'c'")
		require.True(t, rejected.Has("d"), "rejected token should have claim 'd'")
		require.True(t, rejected.Has("e"), "rejected token should have claim 'e'")

		val, ok := rejected.Field("d")
		require.True(t, ok, "rejected.Field should succeed")
		require.Equal(t, "value_d", val, "value for claim 'd' should be preserved")
	})

	t.Run("Filter and Reject do not panic on empty token", func(t *testing.T) {
		token := jwt.New()

		cn := jwtfilter.ByName("a", "b", "c")
		_, err := cn.Filter(token)
		require.NoError(t, err, "cn.Filter should succeed even for an empty token")

		_, err = cn.Reject(token)
		require.NoError(t, err, "cn.Reject should succeed even for an empty token")
	})

	t.Run("Empty name list", func(t *testing.T) {
		cn := jwtfilter.ByName()

		token := jwt.New()
		require.NoError(t, token.Set("a", "value_a"), "token.Set should succeed")
		require.NoError(t, token.Set("b", "value_b"), "token.Set should succeed")
		require.NoError(t, token.Set("c", "value_c"), "token.Set should succeed")

		filtered, err := cn.Filter(token)
		require.NoError(t, err, "cn.Filter should succeed")
		require.Empty(t, filtered.Keys(), "filtered token should have no claims")

		rejected, err := cn.Reject(token)
		require.NoError(t, err, "cn.Reject should succeed")

		originalKeys := token.Keys()
		rejectedKeys := rejected.Keys()
		require.ElementsMatch(t, originalKeys, rejectedKeys, "rejected token should have the same claims as the original")
	})

	t.Run("Concurrency safety", func(t *testing.T) {
		cn := jwtfilter.ByName("a", "b", "c")
		token := jwt.New()
		require.NoError(t, token.Set("a", "value_a"), "token.Set should succeed")
		require.NoError(t, token.Set("d", "value_d"), "token.Set should succeed")

		filtered, err := cn.Filter(token)
		require.NoError(t, err, "cn.Filter should succeed")
		require.True(t, filtered.Has("a"), "filtered token should have claim 'a'")
		require.False(t, filtered.Has("d"), "filtered token should not have claim 'd'")

		rejected, err := cn.Reject(token)
		require.NoError(t, err, "cn.Reject should succeed")
		require.False(t, rejected.Has("a"), "rejected token should not have claim 'a'")
		require.True(t, rejected.Has("d"), "rejected token should have claim 'd'")
	})
}

func TestStandard(t *testing.T) {
	token, err := jwt.NewBuilder().
		Audience([]string{"aud1", "aud2"}).
		Expiration(time.Unix(aLongLongTimeAgo, 0)).
		IssuedAt(time.Unix(aLongLongTimeAgo, 0)).
		Issuer("issuer").
		JwtID("jwt-id").
		NotBefore(time.Unix(aLongLongTimeAgo, 0)).
		Subject("subject").
		Claim("custom1", "value1").
		Claim("custom2", "value2").
		Build()
	require.NoError(t, err, "token should be created successfully")
	require.NotNil(t, token, "token should not be nil")

	stdFilter := jwtfilter.Standard()

	t.Run("Filter standard claims", func(t *testing.T) {
		filtered, err := stdFilter.Filter(token)
		require.NoError(t, err, "filter.Filter should succeed")

		require.True(t, filtered.Has(jwt.AudienceKey), "filtered token should have audience claim")
		require.True(t, filtered.Has(jwt.ExpirationKey), "filtered token should have expiration claim")
		require.True(t, filtered.Has(jwt.IssuedAtKey), "filtered token should have issued-at claim")
		require.True(t, filtered.Has(jwt.IssuerKey), "filtered token should have issuer claim")
		require.True(t, filtered.Has(jwt.JwtIDKey), "filtered token should have jwt-id claim")
		require.True(t, filtered.Has(jwt.NotBeforeKey), "filtered token should have not-before claim")
		require.True(t, filtered.Has(jwt.SubjectKey), "filtered token should have subject claim")

		require.False(t, filtered.Has("custom1"), "filtered token should not have custom1 claim")
		require.False(t, filtered.Has("custom2"), "filtered token should not have custom2 claim")

		issuer, ok := filtered.Field(jwt.IssuerKey)
		require.True(t, ok, "filtered.Field should succeed")
		require.Equal(t, "issuer", issuer, "value for issuer claim should be preserved")
	})

	t.Run("Reject standard claims", func(t *testing.T) {
		rejected, err := stdFilter.Reject(token)
		require.NoError(t, err, "filter.Reject should succeed")

		require.False(t, rejected.Has(jwt.AudienceKey), "rejected token should not have audience claim")
		require.False(t, rejected.Has(jwt.ExpirationKey), "rejected token should not have expiration claim")
		require.False(t, rejected.Has(jwt.IssuedAtKey), "rejected token should not have issued-at claim")
		require.False(t, rejected.Has(jwt.IssuerKey), "rejected token should not have issuer claim")
		require.False(t, rejected.Has(jwt.JwtIDKey), "rejected token should not have jwt-id claim")
		require.False(t, rejected.Has(jwt.NotBeforeKey), "rejected token should not have not-before claim")
		require.False(t, rejected.Has(jwt.SubjectKey), "rejected token should not have subject claim")

		require.True(t, rejected.Has("custom1"), "rejected token should have custom1 claim")
		require.True(t, rejected.Has("custom2"), "rejected token should have custom2 claim")

		customValue, ok := rejected.Field("custom1")
		require.True(t, ok, "rejected.Field should succeed")
		require.Equal(t, "value1", customValue, "value for custom1 claim should be preserved")
	})
}
