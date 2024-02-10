package sqlite

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/bobg/encid"
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
	ks, err := New(ctx, filename, aes.NewCipher)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = ks.DecoderByID(ctx, 1)
	if !errors.Is(err, encid.ErrNotFound) {
		t.Errorf("got %v, want %v", err, encid.ErrNotFound)
	}

	_, _, err = ks.EncoderByType(ctx, 1)
	if !errors.Is(err, encid.ErrNotFound) {
		t.Errorf("got %v, want %v", err, encid.ErrNotFound)
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

func TestErrs(t *testing.T) {
	ctx := context.Background()

	t.Run("NoDir", func(t *testing.T) {
		_, err := New(ctx, "this/directory/does/not/exist/foo.db", aes.NewCipher)
		if err == nil {
			t.Error("got nil, want error")
		}
	})

	tmpdir, err := os.MkdirTemp("", "keystore_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)

	filename := filepath.Join(tmpdir, "keystore.db")
	ks, err := New(ctx, filename, aes.NewCipher)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("NoType", func(t *testing.T) {
		_, _, err := ks.EncoderByType(ctx, 1)
		if !errors.Is(err, encid.ErrNotFound) {
			t.Errorf("got %v, want %v", err, encid.ErrNotFound)
		}
	})

	t.Run("NoID", func(t *testing.T) {
		_, _, err := ks.DecoderByID(ctx, 1)
		if !errors.Is(err, encid.ErrNotFound) {
			t.Errorf("got %v, want %v", err, encid.ErrNotFound)
		}
	})

	t.Run("BadCipher", func(t *testing.T) {
		ks, err := New(ctx, filename, func([]byte) (cipher.Block, error) {
			return nil, errors.New("bad cipher")
		})
		if err != nil {
			t.Fatal(err)
		}
		keyID, err := ks.NewKey(ctx, 1, aes.BlockSize)
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = ks.DecoderByID(ctx, keyID)
		if err == nil {
			t.Error("got nil, want error")
		}
	})
}
