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
	defer func() {
		_ = postgres.Stop()
	}()

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

func setupTestDB(t *testing.T) *KeyStore {
	t.Helper()

	ctx := context.Background()
	db, err := sql.Open("pgx", pgConnStr)
	if err != nil {
		t.Fatalf("opening test db: %v", err)
	}
	defer db.Close()

	if _, err := db.ExecContext(ctx, "DROP TABLE IF EXISTS keys, version, goose_db_version"); err != nil {
		t.Fatalf("resetting schema: %v", err)
	}

	ks, err := New(ctx, pgConnStr, aes.NewCipher)
	if err != nil {
		t.Fatalf("creating test keystore: %v", err)
	}
	t.Cleanup(func() { ks.Close() })

	return ks
}

func TestKeyStore(t *testing.T) {
	if pgConnStr == "" {
		t.Skip("Postgres connection not available")
	}

	testutil.TestKeyStore(t, func(t *testing.T) testutil.KeyStoreTester {
		return setupTestDB(t)
	})
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
