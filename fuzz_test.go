package jwxfilter_test

import (
	"encoding/json"
	"testing"

	"github.com/jwx-go/jwxfilter/v4"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/require"
)

// FuzzAsMap checks that, for any parseable jwt.Token, AsMap populates a map
// whose key set exactly matches the token's own Keys().
func FuzzAsMap(f *testing.F) {
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

	f.Add(seed)
	f.Add([]byte(`{"iss":"issuer"}`))
	f.Add([]byte(`{}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		tok, err := jwt.ParseInsecure(data)
		if err != nil {
			return
		}

		dst := make(map[string]any)
		err = jwxfilter.AsMap(tok, dst)
		require.NoError(t, err, "AsMap must not error on a successfully parsed token")

		dstKeys := make(map[string]struct{}, len(dst))
		for k := range dst {
			dstKeys[k] = struct{}{}
		}

		tokenKeys := make(map[string]struct{}, len(tok.Keys()))
		for _, k := range tok.Keys() {
			tokenKeys[k] = struct{}{}
		}

		require.Equal(t, tokenKeys, dstKeys, "AsMap's key set must exactly match token.Keys()")
	})
}
