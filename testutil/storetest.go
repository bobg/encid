package testutil

import (
	"context"
	"crypto/aes"
	"errors"
	"testing"

	"github.com/bobg/encid/v2"
)

// KeyStoreTester is implemented by keystore implementations or fixtures
// that can be tested with [TestKeyStore].
type KeyStoreTester interface {
	encid.KeyStore
	NewKey(ctx context.Context, typ, keysize int) (int64, error)
}

// TestKeyStore executes the complete encid.KeyStore test suite against the KeyStoreTester produced by factory.
func TestKeyStore(t *testing.T, factory func(t *testing.T) KeyStoreTester) {
	t.Run("NotFound", func(t *testing.T) { testNotFound(t, factory(t)) })
	t.Run("NewKey", func(t *testing.T) { testNewKey(t, factory(t)) })
	t.Run("MultipleKeys", func(t *testing.T) { testMultipleKeys(t, factory(t)) })
	t.Run("EncodeDecode", func(t *testing.T) { testEncodeDecode(t, factory(t)) })
	t.Run("Version", func(t *testing.T) { testVersion(t, factory(t)) })
}

func testNotFound(t *testing.T, ks KeyStoreTester) {
	ctx := context.Background()

	_, _, err := ks.DecoderByID(ctx, 1)
	if !errors.Is(err, encid.ErrNotFound) {
		t.Errorf("DecoderByID: got %v, want %v", err, encid.ErrNotFound)
	}

	_, _, err = ks.EncoderByType(ctx, 1)
	if !errors.Is(err, encid.ErrNotFound) {
		t.Errorf("EncoderByType: got %v, want %v", err, encid.ErrNotFound)
	}
}

func testNewKey(t *testing.T, ks KeyStoreTester) {
	ctx := context.Background()

	id, err := ks.NewKey(ctx, 1, aes.BlockSize)
	if err != nil {
		t.Fatalf("NewKey: %s", err)
	}

	typ, dec, err := ks.DecoderByID(ctx, id)
	if err != nil {
		t.Fatalf("DecoderByID: %s", err)
	}
	if typ != 1 {
		t.Errorf("DecoderByID: got type %d, want 1", typ)
	}
	if dec == nil {
		t.Fatal("DecoderByID: got nil decrypter")
	}

	gotID, enc, err := ks.EncoderByType(ctx, 1)
	if err != nil {
		t.Fatalf("EncoderByType: %s", err)
	}
	if gotID != id {
		t.Errorf("EncoderByType: got ID %d, want %d", gotID, id)
	}
	if enc == nil {
		t.Fatal("EncoderByType: got nil encrypter")
	}

	msg := []byte("0123456789abcdef")
	ciphertext := make([]byte, len(msg))
	decrypted := make([]byte, len(msg))

	enc.Encrypt(ciphertext, msg)
	dec.Decrypt(decrypted, ciphertext)
	if string(decrypted) != string(msg) {
		t.Errorf("decrypted %q != original %q", decrypted, msg)
	}
}

func testMultipleKeys(t *testing.T, ks KeyStoreTester) {
	ctx := context.Background()

	id1, err := ks.NewKey(ctx, 1, aes.BlockSize)
	if err != nil {
		t.Fatalf("NewKey 1: %s", err)
	}

	id2, err := ks.NewKey(ctx, 1, aes.BlockSize)
	if err != nil {
		t.Fatalf("NewKey 2: %s", err)
	}
	if id1 == id2 {
		t.Errorf("expected different key IDs, got %d for both", id1)
	}

	gotID, _, err := ks.EncoderByType(ctx, 1)
	if err != nil {
		t.Fatalf("EncoderByType type 1: %s", err)
	}
	if gotID != id2 {
		t.Errorf("EncoderByType: got ID %d, want newest ID %d", gotID, id2)
	}

	typ1, _, err := ks.DecoderByID(ctx, id1)
	if err != nil {
		t.Fatalf("DecoderByID id1: %s", err)
	}
	if typ1 != 1 {
		t.Errorf("got type %d, want 1", typ1)
	}

	typ2, _, err := ks.DecoderByID(ctx, id2)
	if err != nil {
		t.Fatalf("DecoderByID id2: %s", err)
	}
	if typ2 != 1 {
		t.Errorf("got type %d, want 1", typ2)
	}

	id3, err := ks.NewKey(ctx, 2, aes.BlockSize)
	if err != nil {
		t.Fatalf("NewKey type 2: %s", err)
	}

	gotID3, _, err := ks.EncoderByType(ctx, 2)
	if err != nil {
		t.Fatalf("EncoderByType type 2: %s", err)
	}
	if gotID3 != id3 {
		t.Errorf("got ID %d, want %d", gotID3, id3)
	}

	gotID1, _, err := ks.EncoderByType(ctx, 1)
	if err != nil {
		t.Fatalf("EncoderByType type 1: %s", err)
	}
	if gotID1 != id2 {
		t.Errorf("got ID %d, want %d", gotID1, id2)
	}
}

func testEncodeDecode(t *testing.T, ks KeyStoreTester) {
	ctx := context.Background()

	if _, err := ks.NewKey(ctx, 1, aes.BlockSize); err != nil {
		t.Fatalf("NewKey 1: %s", err)
	}
	if _, err := ks.NewKey(ctx, 2, aes.BlockSize); err != nil {
		t.Fatalf("NewKey 2: %s", err)
	}

	EncodeDecode(ctx, t, ks, 3)
}

func testVersion(t *testing.T, ks KeyStoreTester) {
	v := ks.Version()
	if v != 2 {
		t.Errorf("got version %d, want 2", v)
	}
}
