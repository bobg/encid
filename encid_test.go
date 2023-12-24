package encid_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/bobg/basexx"

	"github.com/bobg/encid"
	"github.com/bobg/encid/testutil"
)

func TestEncodeDecode(t *testing.T) {
	testutil.EncodeDecode(context.Background(), t, testutil.KeyStore{NumTypes: 100}, 100)
}

func TestEncode(t *testing.T) {
	cases := []struct {
		typ       int
		n         int64
		base      basexx.Base
		wantKeyID int64
		wantStr   string
	}{
		{typ: 1, n: 1, wantKeyID: 1, wantStr: "4gsb6bwnsvzdr9sg1wb9f748p1"},
		{typ: 1, n: 2, wantKeyID: 1, wantStr: "141902hrqbyqw88pyfpwpvc1h5w"},
		{typ: 2, n: 1, wantKeyID: 2, wantStr: "18b6557vc00d4n3832j2x8mt3b9"},
		{typ: 1, n: 1, wantKeyID: 1, wantStr: "1zQqKSwhbq2jGRmBNjZctj1", base: basexx.Base50},
		{typ: 1, n: 2, wantKeyID: 1, wantStr: "d4VG7SKjtxtGsSbxzvpCBfw", base: basexx.Base50},
		{typ: 2, n: 1, wantKeyID: 2, wantStr: "fCfbrS0rNNgvsp9gXQ7c2p9", base: basexx.Base50},
	}

	var (
		ks        = testutil.KeyStore{NumTypes: 100}
		zeroBytes zeroByteSource
		ctx       = context.Background()
	)

	for i, c := range cases {
		t.Run(fmt.Sprintf("case_%02d", i+1), func(t *testing.T) {
			base := c.base
			if base == nil {
				base = basexx.Base30
			}

			gotKeyID, gotStr, err := encid.PrivateEncode(ctx, ks, c.typ, c.n, zeroBytes, base)
			if err != nil {
				t.Fatal(err)
			}
			if gotKeyID != c.wantKeyID {
				t.Errorf("got key ID %d, want %d", gotKeyID, c.wantKeyID)
			}

			if gotStr != c.wantStr {
				t.Errorf("got string %s, want %s", gotStr, c.wantStr)
			}
		})
	}
}

func TestDecode(t *testing.T) {
	cases := []struct {
		inpKeyID int64
		inpStr   string
		base     basexx.Base
		wantType int
		wantN    int64
	}{
		{inpKeyID: 1, inpStr: "4gsb6bwnsvzdr9sg1wb9f748p1", wantType: 1, wantN: 1},
		{inpKeyID: 1, inpStr: "141902hrqbyqw88pyfpwpvc1h5w", wantType: 1, wantN: 2},
		{inpKeyID: 2, inpStr: "18b6557vc00d4n3832j2x8mt3b9", wantType: 2, wantN: 1},
		{inpKeyID: 1, inpStr: "1zQqKSwhbq2jGRmBNjZctj1", wantType: 1, wantN: 1, base: basexx.Base50},
		{inpKeyID: 1, inpStr: "d4VG7SKjtxtGsSbxzvpCBfw", wantType: 1, wantN: 2, base: basexx.Base50},
		{inpKeyID: 2, inpStr: "fCfbrS0rNNgvsp9gXQ7c2p9", wantType: 2, wantN: 1, base: basexx.Base50},
	}

	var (
		ks  = testutil.KeyStore{NumTypes: 100}
		ctx = context.Background()
	)

	for i, c := range cases {
		t.Run(fmt.Sprintf("case_%02d", i+1), func(t *testing.T) {
			base := c.base
			if base == nil {
				base = basexx.Base30
			}

			gotType, gotN, err := encid.PrivateDecode(ctx, ks, c.inpKeyID, c.inpStr, base)
			if err != nil {
				t.Fatal(err)
			}
			if gotType != int(c.wantType) {
				t.Errorf("got type %d, want %d", gotType, c.wantType)
			}
			if gotN != c.wantN {
				t.Errorf("got N=%d, want %d", gotN, c.wantN)
			}
		})
	}
}

type zeroByteSource struct{}

func (z zeroByteSource) Read(buf []byte) (int, error) {
	for i := 0; i < len(buf); i++ {
		buf[i] = 0
	}
	return len(buf), nil
}
