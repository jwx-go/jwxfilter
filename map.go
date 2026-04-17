package jwxfilter

import "fmt"

// Mappable is the interface a jwx structure must satisfy to be converted
// to a map[string]any by [AsMap]. jwt.Token, jws.Headers, jwe.Headers, and
// jwk.Key all satisfy it via their existing Field and Keys methods.
//
// EXPERIMENTAL: This API may change or be removed in any release.
type Mappable interface {
	Field(key string) (any, bool)
	Keys() []string
}

// AsMap populates dst with every key/value pair in m. The values written
// into dst are the exact values returned by m.Field(); mutable values such
// as slices, maps, and pointers may alias the original object's backing
// storage. AsMap is not a deep-copy or snapshot helper.
//
// Returns an error if dst is nil.
//
// EXPERIMENTAL: This API may change or be removed in any release.
func AsMap(m Mappable, dst map[string]any) error {
	if dst == nil {
		return fmt.Errorf("jwxfilter.AsMap: destination map cannot be nil")
	}

	for _, k := range m.Keys() {
		if v, ok := m.Field(k); ok {
			dst[k] = v
		}
	}

	return nil
}
