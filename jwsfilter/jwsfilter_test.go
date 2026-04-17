package jwsfilter_test

import (
	"errors"
	"sync"
	"testing"

	"github.com/jwx-go/jwxfilter/v4/jwsfilter"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/stretchr/testify/require"
)

func TestHeaderNameFilter(t *testing.T) {
	t.Run("Basic functionality", func(t *testing.T) {
		fn := jwsfilter.ByName("custom1", "custom3")

		headers := jws.NewHeaders()
		require.NoError(t, headers.Set("custom1", "value1"))
		require.NoError(t, headers.Set("custom2", "value2"))
		require.NoError(t, headers.Set("custom3", "value3"))

		t.Run("Filter specific fields", func(t *testing.T) {
			filtered, err := fn.Filter(headers)
			require.NoError(t, err, "fn.Filter should succeed")

			t.Logf("Original headers keys: %v", headers.Keys())
			t.Logf("Filtered headers keys: %v", filtered.Keys())

			require.True(t, filtered.Has("custom1"), "filtered header should have custom1 field")
			require.True(t, filtered.Has("custom3"), "filtered header should have custom3 field")
			require.False(t, filtered.Has("custom2"), "filtered header should not have custom2 field")
		})

		t.Run("Reject specific fields", func(t *testing.T) {
			rejected, err := fn.Reject(headers)
			require.NoError(t, err, "fn.Reject should succeed")

			require.False(t, rejected.Has("custom1"), "rejected header should not have custom1 field")
			require.False(t, rejected.Has("custom3"), "rejected header should not have custom3 field")
			require.True(t, rejected.Has("custom2"), "rejected header should have custom2 field")
		})
	})

	t.Run("Empty filter", func(t *testing.T) {
		fn := jwsfilter.ByName()

		headers := jws.NewHeaders()
		require.NoError(t, headers.Set(jws.AlgorithmKey, jwa.ES256()))
		require.NoError(t, headers.Set("custom", "value"))

		filtered, err := fn.Filter(headers)
		require.NoError(t, err, "fn.Filter should succeed")
		require.Empty(t, filtered.Keys(), "filtered header should have no fields")

		rejected, err := fn.Reject(headers)
		require.NoError(t, err, "fn.Reject should succeed")

		originalKeys := headers.Keys()
		rejectedKeys := rejected.Keys()
		require.ElementsMatch(t, originalKeys, rejectedKeys, "rejected header should have the same fields as the original")
	})

	t.Run("Concurrency safety", func(t *testing.T) {
		fn := jwsfilter.ByName("custom1")

		headers := jws.NewHeaders()
		require.NoError(t, headers.Set("custom1", "value1"))
		require.NoError(t, headers.Set("custom2", "value2"))

		var wg sync.WaitGroup
		const iterations = 10
		const numGoroutines = 2
		wg.Add(iterations * numGoroutines)
		for range iterations {
			go func() {
				defer wg.Done()
				filtered, err := fn.Filter(headers)
				require.NoError(t, err, "fn.Filter should succeed")
				require.True(t, filtered.Has("custom1"), "filtered header should have custom1 field")
				require.False(t, filtered.Has("custom2"), "filtered header should not have custom2 field")
			}()
			go func() {
				defer wg.Done()
				rejected, err := fn.Reject(headers)
				require.NoError(t, err, "fn.Reject should succeed")
				require.False(t, rejected.Has("custom1"), "rejected header should not have custom1 field")
				require.True(t, rejected.Has("custom2"), "rejected header should have custom2 field")
			}()
		}
		wg.Wait()
	})
}

func TestStandard(t *testing.T) {
	t.Run("Filter standard headers", func(t *testing.T) {
		headers := jws.NewHeaders()
		require.NoError(t, headers.Set("custom1", "value1"))
		require.NoError(t, headers.Set("custom2", "value2"))

		stdFilter := jwsfilter.Standard()

		t.Run("Filter standard headers", func(t *testing.T) {
			filtered, err := stdFilter.Filter(headers)
			require.NoError(t, err, "filter.Filter should succeed")

			require.Empty(t, filtered.Keys(), "filtered header should have no fields")

			require.False(t, filtered.Has("custom1"), "filtered header should not have custom1 field")
			require.False(t, filtered.Has("custom2"), "filtered header should not have custom2 field")
		})

		t.Run("Reject standard headers", func(t *testing.T) {
			rejected, err := stdFilter.Reject(headers)
			require.NoError(t, err, "filter.Reject should succeed")

			require.True(t, rejected.Has("custom1"), "rejected header should have custom1 field")
			require.True(t, rejected.Has("custom2"), "rejected header should have custom2 field")

			originalKeys := headers.Keys()
			rejectedKeys := rejected.Keys()
			require.ElementsMatch(t, originalKeys, rejectedKeys, "rejected should have all original fields")

			customValue, ok := rejected.Field("custom1")
			require.True(t, ok, "rejected.Field should succeed")
			require.Equal(t, "value1", customValue, "value for custom1 field should be preserved")
		})
	})
}

type errorHeaders struct {
	jws.Headers
}

func (h *errorHeaders) Clone() (jws.Headers, error) {
	return nil, errors.New("forced Clone error")
}

func (h *errorHeaders) Keys() []string {
	return []string{}
}

func TestHeaderFilterErrors(t *testing.T) {
	badHeaders := &errorHeaders{jws.NewHeaders()}
	filter := jwsfilter.ByName("test")

	t.Run("Filter error handling", func(t *testing.T) {
		_, err := filter.Filter(badHeaders)
		require.Error(t, err, "filter.Filter should fail with errorHeaders")
		require.Contains(t, err.Error(), "forced Clone error", "error message should include Clone error")
	})

	t.Run("Reject error handling", func(t *testing.T) {
		_, err := filter.Reject(badHeaders)
		require.Error(t, err, "filter.Reject should fail with errorHeaders")
		require.Contains(t, err.Error(), "forced Clone error", "error message should include Clone error")
	})
}
