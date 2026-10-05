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

	"github.com/bobg/encid/v2/testutil"
)

func TestKeyStore(t *testing.T) {
	testutil.TestKeyStore(t, func(t *testing.T) testutil.KeyStoreTester {
		tmpdir, err := os.MkdirTemp("", "keystore_test")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.RemoveAll(tmpdir) })

		ctx := context.Background()
		filename := filepath.Join(tmpdir, "keystore.db")
		ks, err := New(ctx, filename, aes.NewCipher)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ks.Close() })

		return ks
	})
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
	defer ks.Close()

	t.Run("BadCipher", func(t *testing.T) {
		ks, err := New(ctx, filename, func([]byte) (cipher.Block, error) {
			return nil, errors.New("bad cipher")
		})
		if err != nil {
			t.Fatal(err)
		}
		defer ks.Close()

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

func TestNewFromDB(t *testing.T) {
	tmpdir, err := os.MkdirTemp("", "keystore_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)

	ctx := context.Background()

	filename := filepath.Join(tmpdir, "keystore.db")
	db, err := sql.Open("sqlite3", filename)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ks, err := NewFromDB(ctx, db, false, aes.NewCipher)
	if err != nil {
		t.Fatal(err)
	}
	if err := ks.Close(); err != nil {
		t.Fatal(err)
	}

	if err := db.PingContext(ctx); err != nil {
		t.Errorf("db should still be pingable after closing unowned keystore: %v", err)
	}
}
