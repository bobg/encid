package encid_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/bobg/basexx/v2"

	"github.com/bobg/encid/v2"
	"github.com/bobg/encid/v2/testutil"
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
		{typ: 1, n: 1, wantKeyID: 1, wantStr: "2dcs989dst8224g2rrvg580skz"},
		{typ: 1, n: 2, wantKeyID: 1, wantStr: "6fyky9nsyqh8943gmshzz8jpdb"},
		{typ: 2, n: 1, wantKeyID: 2, wantStr: "14t5j1khfx4j7m1njgqyyzjtz2b"},
		{typ: 1, n: 1, wantKeyID: 1, wantStr: "RSTSt7Bs245WRrsf1hr0tN", base: basexx.Base50},
		{typ: 1, n: 2, wantKeyID: 1, wantStr: "2gSV8M1XJdX6yN0rPqrq27p", base: basexx.Base50},
		{typ: 2, n: 1, wantKeyID: 2, wantStr: "dmsp5FPBFscc65JFzftrFFp", base: basexx.Base50},
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
		{inpKeyID: 1, inpStr: "2dcs989dst8224g2rrvg580skz", wantType: 1, wantN: 1},
		{inpKeyID: 1, inpStr: "6fyky9nsyqh8943gmshzz8jpdb", wantType: 1, wantN: 2},
		{inpKeyID: 2, inpStr: "14t5j1khfx4j7m1njgqyyzjtz2b", wantType: 2, wantN: 1},
		{inpKeyID: 1, inpStr: "RSTSt7Bs245WRrsf1hr0tN", wantType: 1, wantN: 1, base: basexx.Base50},
		{inpKeyID: 1, inpStr: "2gSV8M1XJdX6yN0rPqrq27p", wantType: 1, wantN: 2, base: basexx.Base50},
		{inpKeyID: 2, inpStr: "dmsp5FPBFscc65JFzftrFFp", wantType: 2, wantN: 1, base: basexx.Base50},
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

func TestErrs(t *testing.T) {
	var (
		ctx = context.Background()
		ks  = testutil.KeyStore{NumTypes: 1}
	)

	t.Run("Encode50", func(t *testing.T) {
		_, _, err := encid.Encode50(ctx, ks, 1000000, 1)
		if !errors.Is(err, encid.ErrNotFound) {
			t.Errorf("got error %v, want %v", err, encid.ErrNotFound)
		}
	})

	t.Run("Decode50", func(t *testing.T) {
		_, _, err := encid.Decode50(ctx, ks, 1000000, "1zQqKSwhbq2jGRmBNjZctj1")
		if !errors.Is(err, encid.ErrNotFound) {
			t.Errorf("got error %v, want %v", err, encid.ErrNotFound)
		}
	})

	t.Run("BadBase50", func(t *testing.T) {
		_, _, err := encid.Decode50(ctx, ks, 1, "aeiou")
		if !errors.Is(err, basexx.ErrInvalid) {
			t.Errorf("got error %v, want %v", err, basexx.ErrInvalid)
		}
	})
}
