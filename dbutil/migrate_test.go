package dbutil

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"testing/fstest"

	_ "github.com/mattn/go-sqlite3"
	"github.com/pressly/goose/v3"
)

func TestMigrateSchema(t *testing.T) {
	ctx := context.Background()

	testMigrations := fstest.MapFS{
		"migrations/20261001000000_init.sql": &fstest.MapFile{
			Data: []byte("-- +goose Up\nCREATE TABLE test_tab (id INTEGER PRIMARY KEY);\n"),
		},
		"migrations/20261006134557_cutoff.sql": &fstest.MapFile{
			Data: []byte("-- +goose Up\nALTER TABLE test_tab ADD COLUMN col1 TEXT;\n"),
		},
		"migrations/20261008000000_future.sql": &fstest.MapFile{
			Data: []byte("-- +goose Up\nALTER TABLE test_tab ADD COLUMN col2 TEXT;\n"),
		},
	}
	initSQL := `
		CREATE TABLE test_tab (id INTEGER PRIMARY KEY, col1 TEXT);
	`

	t.Run("DefaultTable", func(t *testing.T) {
		tmpdir := t.TempDir()
		db, err := sql.Open("sqlite3", filepath.Join(tmpdir, "test.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close() // nolint:errcheck

		if err := Migrate(ctx, db, goose.DialectSQLite3, testMigrations, initSQL, InitialCutoff); err != nil {
			t.Fatalf("Migrate failed: %v", err)
		}

		var count int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM goose_db_version`).Scan(&count); err != nil {
			t.Fatalf("goose_db_version should exist: %v", err)
		}
		if count == 0 {
			t.Error("goose_db_version should have records")
		}

		// Verify col2 exists (future migration was applied).
		if _, err := db.ExecContext(ctx, `SELECT col2 FROM test_tab`); err != nil {
			t.Errorf("future migration was not applied: %v", err)
		}
	})

	t.Run("CustomTable", func(t *testing.T) {
		tmpdir := t.TempDir()
		db, err := sql.Open("sqlite3", filepath.Join(tmpdir, "test.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close() // nolint:errcheck

		if err := MigrateSchema(ctx, db, goose.DialectSQLite3, testMigrations, initSQL, InitialCutoff, "my_custom_migrations"); err != nil {
			t.Fatalf("MigrateSchema failed: %v", err)
		}

		var count int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM my_custom_migrations`).Scan(&count); err != nil {
			t.Fatalf("my_custom_migrations should exist: %v", err)
		}
		if count == 0 {
			t.Error("my_custom_migrations should have records")
		}

		var exists int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='goose_db_version'`).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if exists != 0 {
			t.Errorf("goose_db_version should not exist, found %d", exists)
		}

		// Verify col2 exists (future migration was applied).
		if _, err := db.ExecContext(ctx, `SELECT col2 FROM test_tab`); err != nil {
			t.Errorf("future migration was not applied: %v", err)
		}
	})

	t.Run("CustomTableRejectsExistingSchema", func(t *testing.T) {
		tmpdir := t.TempDir()
		db, err := sql.Open("sqlite3", filepath.Join(tmpdir, "test.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close() // nolint:errcheck

		_, err = db.ExecContext(ctx, `
			CREATE TABLE keys (id INTEGER PRIMARY KEY, typ INTEGER, k BLOB);
			CREATE TABLE version (singleton INTEGER PRIMARY KEY, version INTEGER);
			CREATE TABLE goose_db_version (version_id INTEGER NOT NULL, is_applied BOOLEAN NOT NULL);
			INSERT INTO keys (id, typ, k) VALUES (1, 10, X'01');
			INSERT INTO goose_db_version (version_id, is_applied) VALUES (0, 1), (20261001000000, 1);
		`)
		if err != nil {
			t.Fatal(err)
		}

		if err := MigrateSchema(ctx, db, goose.DialectSQLite3, testMigrations, initSQL, InitialCutoff, "my_custom_migrations"); err == nil {
			t.Fatal("MigrateSchema should reject an existing schema with an empty custom migrations table")
		}

		var count int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM keys`).Scan(&count); err != nil {
			t.Fatalf("existing keys table should remain accessible: %v", err)
		}
		if count != 1 {
			t.Errorf("existing keys table should retain its row, got %d", count)
		}

		var exists int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'encid_keys'`).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if exists != 0 {
			t.Error("encid_keys should not be created before rejecting the existing schema")
		}
	})

	t.Run("EmptyTableNameUsesDefault", func(t *testing.T) {
		tmpdir := t.TempDir()
		db, err := sql.Open("sqlite3", filepath.Join(tmpdir, "test.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close() // nolint:errcheck

		if err := MigrateSchema(ctx, db, goose.DialectSQLite3, testMigrations, initSQL, InitialCutoff, ""); err != nil {
			t.Fatalf("MigrateSchema failed: %v", err)
		}

		var count int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM goose_db_version`).Scan(&count); err != nil {
			t.Fatalf("goose_db_version should exist: %v", err)
		}
		if count == 0 {
			t.Error("goose_db_version should have records")
		}
	})
}
