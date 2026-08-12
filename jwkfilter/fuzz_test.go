package jwkfilter_test

import (
	"strings"
	"testing"

	"github.com/jwx-go/jwxfilter/v4/jwkfilter"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/stretchr/testify/require"
)

// FuzzFilterRejectPartition checks that, for any parseable jwk.Key and any
// name set, Filter and Reject partition the key's field names: the two
// results never share a field, and together they account for every field on
// the original key.
//
// kty is excluded from that partition check. Per the jwkfilter package doc,
// jwk.Key.Remove("kty") is a documented no-op ("kty cannot be removed...
// Reject results always retain kty even when 'kty' is in the configured
// name set... [t]reat this as a guaranteed invariant rather than a
// deviation"), so kty always survives into both Filter's and Reject's
// results regardless of the configured name set. That makes kty land in
// both sets simultaneously, which the general partition property forbids.
// Rather than let the fuzz target merely tolerate that, it pins the
// documented behavior down explicitly: kty is required to be present in
// both results, and the partition property is checked on every other
// field.
func FuzzFilterRejectPartition(f *testing.F) {
	const seed = `{
		"kty": "oct",
		"k": "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
		"kid": "kid-value",
		"custom": "value"
	}`

	f.Add([]byte(seed), "")
	f.Add([]byte(seed), jwk.KeyIDKey)
	f.Add([]byte(seed), jwk.KeyTypeKey+","+jwk.KeyIDKey)
	f.Add([]byte(seed), "not-a-field")

	f.Fuzz(func(t *testing.T, data []byte, names string) {
		key, err := jwk.ParseKeyAs[jwk.Key](data)
		if err != nil {
			return
		}

		filter := jwkfilter.ByName(strings.Split(names, ",")...)

		filtered, err := filter.Filter(key)
		require.NoError(t, err, "Filter must not error on a successfully parsed key")

		rejected, err := filter.Reject(key)
		require.NoError(t, err, "Reject must not error on a successfully parsed key")

		filteredKeys := filtered.Keys()
		rejectedKeys := rejected.Keys()

		require.Contains(t, filteredKeys, jwk.KeyTypeKey, "kty must always survive Filter (Remove(\"kty\") is a documented no-op)")
		require.Contains(t, rejectedKeys, jwk.KeyTypeKey, "kty must always survive Reject (Remove(\"kty\") is a documented no-op)")

		requirePartitionExcluding(t, key.Keys(), filteredKeys, rejectedKeys, jwk.KeyTypeKey)
	})
}

// requirePartitionExcluding asserts that filtered and rejected are disjoint
// and that their union equals original, treating all three as sets of field
// names, after removing excluded from all three sets first.
func requirePartitionExcluding(t *testing.T, original, filtered, rejected []string, excluded string) {
	t.Helper()

	originalSet := toSet(original)
	filteredSet := toSet(filtered)
	rejectedSet := toSet(rejected)

	delete(originalSet, excluded)
	delete(filteredSet, excluded)
	delete(rejectedSet, excluded)

	for k := range filteredSet {
		_, ok := rejectedSet[k]
		require.False(t, ok, "field %q present in both Filter and Reject results", k)
	}

	union := make(map[string]struct{}, len(filteredSet)+len(rejectedSet))
	for k := range filteredSet {
		union[k] = struct{}{}
	}
	for k := range rejectedSet {
		union[k] = struct{}{}
	}

	require.Equal(t, originalSet, union, "Filter and Reject results together must cover exactly the original fields, excluding kty")
}

func toSet(keys []string) map[string]struct{} {
	m := make(map[string]struct{}, len(keys))
	for _, k := range keys {
		m[k] = struct{}{}
	}
	return m
}
