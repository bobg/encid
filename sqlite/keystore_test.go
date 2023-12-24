package sqlite

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/bobg/encid/testutil"
)

func TestKeyStore(t *testing.T) {
	tmpdir, err := os.MkdirTemp("", "keystore_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)

	ctx := context.Background()

	filename := filepath.Join(tmpdir, "keystore.db")
	ks, err := New(ctx, filename, func(key []byte) (cipher.Block, error) {
		return aes.NewCipher(key)
	})
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = ks.DecoderByID(ctx, 1)
	if !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("got %v, want %v", err, sql.ErrNoRows)
	}

	_, _, err = ks.EncoderByType(ctx, 1)
	if !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("got %v, want %v", err, sql.ErrNoRows)
	}

	id, err := ks.NewKey(ctx, 1, aes.BlockSize)
	if err != nil {
		t.Fatal(err)
	}

	typ, _, err := ks.DecoderByID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if typ != 1 {
		t.Errorf("got type %d, want 1", typ)
	}

	gotID, _, err := ks.EncoderByType(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if gotID != id {
		t.Errorf("got ID %d, want %d", gotID, id)
	}

	_, err = ks.NewKey(ctx, 2, aes.BlockSize)
	if err != nil {
		t.Fatal(err)
	}

	testutil.EncodeDecode(ctx, t, ks, 2)
}
