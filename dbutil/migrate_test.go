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
		defer db.Close()

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
		defer db.Close()

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

	t.Run("EmptyTableNameUsesDefault", func(t *testing.T) {
		tmpdir := t.TempDir()
		db, err := sql.Open("sqlite3", filepath.Join(tmpdir, "test.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()

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
