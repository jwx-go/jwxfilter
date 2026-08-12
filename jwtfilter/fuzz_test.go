package jwtfilter_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/jwx-go/jwxfilter/v4/jwtfilter"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/require"
)

// FuzzFilterRejectPartition checks that, for any parseable jwt.Token and any
// name set, Filter and Reject partition the token's claim names: the two
// results never share a claim, and together they account for every claim on
// the original token.
func FuzzFilterRejectPartition(f *testing.F) {
	token, err := jwt.NewBuilder().
		Issuer("issuer").
		Subject("subject").
		Claim("custom", "value").
		Build()
	if err != nil {
		f.Fatal(err)
	}
	seed, err := json.Marshal(token)
	if err != nil {
		f.Fatal(err)
	}

	f.Add(seed, "")
	f.Add(seed, jwt.IssuerKey)
	f.Add(seed, jwt.IssuerKey+","+jwt.SubjectKey)
	f.Add(seed, "not-a-claim")

	f.Fuzz(func(t *testing.T, data []byte, names string) {
		tok, err := jwt.ParseInsecure(data)
		if err != nil {
			return
		}

		filter := jwtfilter.ByName(strings.Split(names, ",")...)

		filtered, err := filter.Filter(tok)
		require.NoError(t, err, "Filter must not error on a successfully parsed token")

		rejected, err := filter.Reject(tok)
		require.NoError(t, err, "Reject must not error on a successfully parsed token")

		requirePartition(t, tok.Keys(), filtered.Keys(), rejected.Keys())
	})
}

// requirePartition asserts that filtered and rejected are disjoint and that
// their union equals original, treating all three as sets of claim names.
func requirePartition(t *testing.T, original, filtered, rejected []string) {
	t.Helper()

	originalSet := toSet(original)
	filteredSet := toSet(filtered)
	rejectedSet := toSet(rejected)

	for k := range filteredSet {
		_, ok := rejectedSet[k]
		require.False(t, ok, "claim %q present in both Filter and Reject results", k)
	}

	union := make(map[string]struct{}, len(filteredSet)+len(rejectedSet))
	for k := range filteredSet {
		union[k] = struct{}{}
	}
	for k := range rejectedSet {
		union[k] = struct{}{}
	}

	require.Equal(t, originalSet, union, "Filter and Reject results together must cover exactly the original claims")
}

func toSet(keys []string) map[string]struct{} {
	m := make(map[string]struct{}, len(keys))
	for _, k := range keys {
		m[k] = struct{}{}
	}
	return m
}
