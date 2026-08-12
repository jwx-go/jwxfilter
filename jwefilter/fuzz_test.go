package jwefilter_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/jwx-go/jwxfilter/v4/jwefilter"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwe"
	"github.com/stretchr/testify/require"
)

// FuzzFilterRejectPartition checks that, for any parseable jwe.Headers and
// any name set, Filter and Reject partition the header's field names: the
// two results never share a field, and together they account for every
// field on the original headers.
func FuzzFilterRejectPartition(f *testing.F) {
	headers := jwe.NewHeaders()
	if err := headers.Set(jwe.AlgorithmKey, jwa.RSA_OAEP_256()); err != nil {
		f.Fatal(err)
	}
	if err := headers.Set(jwe.KeyIDKey, "kid-value"); err != nil {
		f.Fatal(err)
	}
	if err := headers.Set("custom", "value"); err != nil {
		f.Fatal(err)
	}
	seed, err := json.Marshal(headers)
	if err != nil {
		f.Fatal(err)
	}

	f.Add(seed, "")
	f.Add(seed, jwe.AlgorithmKey)
	f.Add(seed, jwe.AlgorithmKey+","+jwe.KeyIDKey)
	f.Add(seed, "not-a-field")

	f.Fuzz(func(t *testing.T, data []byte, names string) {
		hdrs := jwe.NewHeaders()
		if err := json.Unmarshal(data, hdrs); err != nil {
			return
		}

		filter := jwefilter.ByName(strings.Split(names, ",")...)

		filtered, err := filter.Filter(hdrs)
		require.NoError(t, err, "Filter must not error on successfully parsed headers")

		rejected, err := filter.Reject(hdrs)
		require.NoError(t, err, "Reject must not error on successfully parsed headers")

		requirePartition(t, hdrs.Keys(), filtered.Keys(), rejected.Keys())
	})
}

// requirePartition asserts that filtered and rejected are disjoint and that
// their union equals original, treating all three as sets of field names.
func requirePartition(t *testing.T, original, filtered, rejected []string) {
	t.Helper()

	originalSet := toSet(original)
	filteredSet := toSet(filtered)
	rejectedSet := toSet(rejected)

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

	require.Equal(t, originalSet, union, "Filter and Reject results together must cover exactly the original fields")
}

func toSet(keys []string) map[string]struct{} {
	m := make(map[string]struct{}, len(keys))
	for _, k := range keys {
		m[k] = struct{}{}
	}
	return m
}
