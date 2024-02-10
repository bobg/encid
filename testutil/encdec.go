package testutil

import (
	"context"
	"testing"
	"testing/quick"

	"github.com/bobg/encid"
)

func EncodeDecode(ctx context.Context, t *testing.T, ks encid.KeyStore, numTypes int) {
	err := quick.Check(func(n int64) bool {
		if n <= 0 {
			return true
		}
		for typ := 1; typ < numTypes; typ++ {
			keyID, str, err := encid.Encode(ctx, ks, typ, n)
			if err != nil {
				t.Logf("Error encoding (%d, %d): %s", typ, n, err)
				return false
			}
			gotTyp, gotN, err := encid.Decode(ctx, ks, keyID, str)
			if err != nil {
				t.Logf("Error decoding (%d, %s): %s\n", keyID, str, err)
				return false
			}
			if gotTyp != typ || gotN != n {
				t.Logf("Decode(Encode(%d, %d)) = (%d, %d)", typ, n, gotTyp, gotN)
				return false
			}
		}
		return true
	}, nil)
	if err != nil {
		t.Error(err)
	}
}
