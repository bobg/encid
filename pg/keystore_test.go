package pg

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"os"
	"testing"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"

	"github.com/bobg/encid/v2"
	"github.com/bobg/encid/v2/testutil"
)

var pgConnStr string

func TestMain(m *testing.M) {
	connStr := os.Getenv("POSTGRES_URL")
	if connStr == "" {
		connStr = os.Getenv("PG_URL")
	}

	if connStr != "" {
		pgConnStr = connStr
		os.Exit(m.Run())
	}

	port := getFreePort()
	postgres := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().Port(port))
	if err := postgres.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to start embedded postgres on port %d: %v\n", port, err)
		os.Exit(1)
	}
	defer postgres.Stop()

	pgConnStr = fmt.Sprintf("postgres://postgres:postgres@127.0.0.1:%d/postgres?sslmode=disable", port)
	os.Exit(m.Run())
}

func getFreePort() uint32 {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 15432
	}
	defer l.Close()
	return uint32(l.Addr().(*net.TCPAddr).Port)
}

func TestKeyStore(t *testing.T) {
	if pgConnStr == "" {
		t.Skip("Postgres connection not available")
	}

	ctx := context.Background()

	db, err := sql.Open("pgx", pgConnStr)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// Clean up database tables before running the test
	if _, err := db.ExecContext(ctx, "DROP TABLE IF EXISTS keys, version, goose_db_version"); err != nil {
		t.Fatal(err)
	}

	ks, err := New(ctx, pgConnStr, aes.NewCipher)
	if err != nil {
		t.Fatal(err)
	}
	defer ks.Close()

	if v := ks.Version(); v != 2 {
		t.Errorf("got version %d, want 2", v)
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
	if pgConnStr == "" {
		t.Skip("Postgres connection not available")
	}

	ctx := context.Background()

	t.Run("BadConn", func(t *testing.T) {
		_, err := New(ctx, "postgres://invalid:invalid@127.0.0.1:1/nonexistent?sslmode=disable", aes.NewCipher)
		if err == nil {
			t.Error("got nil, want error")
		}
	})

	db, err := sql.Open("pgx", pgConnStr)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if _, err := db.ExecContext(ctx, "DROP TABLE IF EXISTS keys, version, goose_db_version"); err != nil {
		t.Fatal(err)
	}

	ks, err := New(ctx, pgConnStr, aes.NewCipher)
	if err != nil {
		t.Fatal(err)
	}
	defer ks.Close()

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
		ksBad, err := New(ctx, pgConnStr, func([]byte) (cipher.Block, error) {
			return nil, errors.New("bad cipher")
		})
		if err != nil {
			t.Fatal(err)
		}
		defer ksBad.Close()

		keyID, err := ksBad.NewKey(ctx, 1, aes.BlockSize)
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = ksBad.DecoderByID(ctx, keyID)
		if err == nil {
			t.Error("got nil, want error")
		}
	})
}

func TestNewFromDB(t *testing.T) {
	if pgConnStr == "" {
		t.Skip("Postgres connection not available")
	}

	ctx := context.Background()

	db, err := sql.Open("pgx", pgConnStr)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if _, err := db.ExecContext(ctx, "DROP TABLE IF EXISTS keys, version, goose_db_version"); err != nil {
		t.Fatal(err)
	}

	ks, err := NewFromDB(ctx, db, false, aes.NewCipher)
	if err != nil {
		t.Fatal(err)
	}
	if err := ks.Close(); err != nil {
		t.Fatal(err)
	}

	// Verify db is still open when own is false
	if err := db.PingContext(ctx); err != nil {
		t.Errorf("db should still be pingable after closing unowned keystore: %v", err)
	}
}
