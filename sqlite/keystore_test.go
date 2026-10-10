package sqlite

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"

	"github.com/pressly/goose/v3"

	"github.com/bobg/encid/v2/dbutil"
	"github.com/bobg/encid/v2/testutil"
)

func TestKeyStore(t *testing.T) {
	testutil.TestKeyStore(t, func(t *testing.T) testutil.KeyStoreTester {
		tmpdir, err := os.MkdirTemp("", "keystore_test")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.RemoveAll(tmpdir) }) // nolint:errcheck

		ctx := context.Background()
		filename := filepath.Join(tmpdir, "keystore.db")
		ks, err := New(ctx, filename, aes.NewCipher)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ks.Close() }) // nolint:errcheck

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
	defer os.RemoveAll(tmpdir) // nolint:errcheck

	filename := filepath.Join(tmpdir, "keystore.db")
	ks, err := New(ctx, filename, aes.NewCipher)
	if err != nil {
		t.Fatal(err)
	}
	defer ks.Close() // nolint:errcheck

	t.Run("BadCipher", func(t *testing.T) {
		ks, err := New(ctx, filename, func([]byte) (cipher.Block, error) {
			return nil, errors.New("bad cipher")
		})
		if err != nil {
			t.Fatal(err)
		}
		defer ks.Close() // nolint:errcheck

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
	defer os.RemoveAll(tmpdir) // nolint:errcheck

	ctx := context.Background()

	filename := filepath.Join(tmpdir, "keystore.db")
	db, err := sql.Open("sqlite3", filename)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close() // nolint:errcheck

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

func TestMigrations(t *testing.T) {
	ctx := context.Background()

	t.Run("NewDatabaseNoOldTables", func(t *testing.T) {
		tmpdir, err := os.MkdirTemp("", "keystore_test")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(tmpdir) // nolint:errcheck

		filename := filepath.Join(tmpdir, "keystore.db")
		db, err := sql.Open("sqlite3", filename)
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close() // nolint:errcheck

		ks, err := NewFromDB(ctx, db, false, aes.NewCipher)
		if err != nil {
			t.Fatal(err)
		}
		defer ks.Close() // nolint:errcheck

		// Verify encid_keys and encid_version exist.
		var count int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM encid_keys`).Scan(&count); err != nil {
			t.Fatalf("encid_keys should exist: %v", err)
		}
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM encid_version`).Scan(&count); err != nil {
			t.Fatalf("encid_version should exist: %v", err)
		}

		// Verify keys and version do NOT exist.
		var exists int
		err = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('keys', 'version')`).Scan(&exists)
		if err != nil {
			t.Fatal(err)
		}
		if exists != 0 {
			t.Errorf("unprefixed tables 'keys' or 'version' should not exist in new database, found %d", exists)
		}
	})

	t.Run("ExistingDatabaseWithHostTables", func(t *testing.T) {
		tmpdir, err := os.MkdirTemp("", "keystore_test")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(tmpdir) // nolint:errcheck

		filename := filepath.Join(tmpdir, "keystore.db")
		db, err := sql.Open("sqlite3", filename)
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close() // nolint:errcheck

		// Simulate pre-existing host application tables named `keys` and `version`.
		_, err = db.ExecContext(ctx, `
			CREATE TABLE keys (custom_col TEXT);
			INSERT INTO keys VALUES ('my-app-key');
			CREATE TABLE version (app_version INTEGER);
			INSERT INTO version VALUES (42);
		`)
		if err != nil {
			t.Fatal(err)
		}

		ks, err := NewFromDB(ctx, db, false, aes.NewCipher)
		if err != nil {
			t.Fatal(err)
		}
		defer ks.Close() // nolint:errcheck

		// Verify the host application's tables are unmodified.
		var customVal string
		if err := db.QueryRowContext(ctx, `SELECT custom_col FROM keys`).Scan(&customVal); err != nil {
			t.Fatalf("host 'keys' table query failed: %v", err)
		}
		if customVal != "my-app-key" {
			t.Errorf("host 'keys' content got %q, want 'my-app-key'", customVal)
		}

		var appVer int
		if err := db.QueryRowContext(ctx, `SELECT app_version FROM version`).Scan(&appVer); err != nil {
			t.Fatalf("host 'version' table query failed: %v", err)
		}
		if appVer != 42 {
			t.Errorf("host 'version' content got %d, want 42", appVer)
		}

		// Verify encid tables work properly alongside host tables.
		keyID, err := ks.NewKey(ctx, 1, aes.BlockSize)
		if err != nil {
			t.Fatalf("NewKey failed: %v", err)
		}
		typ, _, err := ks.DecoderByID(ctx, keyID)
		if err != nil {
			t.Fatalf("DecoderByID failed: %v", err)
		}
		if typ != 1 {
			t.Errorf("got key type %d, want 1", typ)
		}
	})

	t.Run("DatabaseWithOldEncidMigrations", func(t *testing.T) {
		tmpdir, err := os.MkdirTemp("", "keystore_test")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(tmpdir) // nolint:errcheck

		filename := filepath.Join(tmpdir, "keystore.db")
		db, err := sql.Open("sqlite3", filename)
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close() // nolint:errcheck

		// Simulate database created by an older version of encid (e.g. migration 20231222024441).
		// Create keys table and goose_db_version with migration 20231222024441 applied.
		_, err = db.ExecContext(ctx, `
			CREATE TABLE goose_db_version (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				version_id INTEGER NOT NULL,
				is_applied INTEGER NOT NULL,
				tstamp TIMESTAMP DEFAULT (datetime('now'))
			);
			INSERT INTO goose_db_version (version_id, is_applied) VALUES (0, 1), (20231222024441, 1);
			CREATE TABLE keys (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				typ INTEGER NOT NULL,
				k BLOB NOT NULL
			);
			CREATE INDEX keys_typ_index ON keys (typ);
			INSERT INTO keys (id, typ, k) VALUES (1, 10, X'0102030405060708090a0b0c0d0e0f10');
		`)
		if err != nil {
			t.Fatal(err)
		}

		ks, err := NewFromDB(ctx, db, false, aes.NewCipher)
		if err != nil {
			t.Fatal(err)
		}
		defer ks.Close() // nolint:errcheck

		// Migration should have run goose Up, renaming keys to encid_keys and creating encid_version.
		typ, _, err := ks.DecoderByID(ctx, 1)
		if err != nil {
			t.Fatalf("DecoderByID for pre-existing key failed: %v", err)
		}
		if typ != 10 {
			t.Errorf("got type %d, want 10", typ)
		}

		// Since nkeys > 0 initially, version should be 1.
		if ks.Version() != 1 {
			t.Errorf("got version %d, want 1", ks.Version())
		}
	})

	t.Run("CustomMigrationsTable", func(t *testing.T) {
		tmpdir, err := os.MkdirTemp("", "keystore_test")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(tmpdir) // nolint:errcheck

		origTable := MigrationsTable
		MigrationsTable = "custom_goose_version"
		t.Cleanup(func() { MigrationsTable = origTable })

		filename := filepath.Join(tmpdir, "keystore.db")
		db, err := sql.Open("sqlite3", filename)
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close() // nolint:errcheck

		ks, err := NewFromDB(ctx, db, false, aes.NewCipher)
		if err != nil {
			t.Fatal(err)
		}
		defer ks.Close() // nolint:errcheck

		// Verify custom migrations table exists and recorded migrations.
		var count int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM custom_goose_version`).Scan(&count); err != nil {
			t.Fatalf("custom_goose_version table should exist: %v", err)
		}
		if count == 0 {
			t.Error("custom_goose_version table should have recorded migrations, got 0")
		}

		// Verify default goose_db_version does NOT exist.
		var exists int
		err = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='goose_db_version'`).Scan(&exists)
		if err != nil {
			t.Fatal(err)
		}
		if exists != 0 {
			t.Errorf("goose_db_version should not exist when MigrationsTable is customized, found %d", exists)
		}

		// Verify keystore works normally.
		keyID, err := ks.NewKey(ctx, 1, aes.BlockSize)
		if err != nil {
			t.Fatalf("NewKey failed: %v", err)
		}
		typ, _, err := ks.DecoderByID(ctx, keyID)
		if err != nil {
			t.Fatalf("DecoderByID failed: %v", err)
		}
		if typ != 1 {
			t.Errorf("got key type %d, want 1", typ)
		}
	})

	t.Run("CoexistingGooseSchemas", func(t *testing.T) {
		tmpdir, err := os.MkdirTemp("", "keystore_test")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(tmpdir) // nolint:errcheck

		filename := filepath.Join(tmpdir, "keystore.db")
		db, err := sql.Open("sqlite3", filename)
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close() // nolint:errcheck

		// Host application creates its own goose_db_version table and host table.
		_, err = db.ExecContext(ctx, `
			CREATE TABLE goose_db_version (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				version_id INTEGER NOT NULL,
				is_applied INTEGER NOT NULL,
				tstamp TIMESTAMP DEFAULT (datetime('now'))
			);
			INSERT INTO goose_db_version (version_id, is_applied) VALUES (0, 1), (100, 1);
			CREATE TABLE host_items (
				id INTEGER PRIMARY KEY,
				name TEXT NOT NULL
			);
			INSERT INTO host_items (id, name) VALUES (1, 'item-one');
		`)
		if err != nil {
			t.Fatal(err)
		}

		origTable := MigrationsTable
		MigrationsTable = "encid_schema_version"
		t.Cleanup(func() { MigrationsTable = origTable })

		ks, err := NewFromDB(ctx, db, false, aes.NewCipher)
		if err != nil {
			t.Fatal(err)
		}
		defer ks.Close() // nolint:errcheck

		// Verify host data is intact.
		var hostName string
		if err := db.QueryRowContext(ctx, `SELECT name FROM host_items WHERE id = 1`).Scan(&hostName); err != nil {
			t.Fatalf("reading host_items failed: %v", err)
		}
		if hostName != "item-one" {
			t.Errorf("got host_items name %q, want 'item-one'", hostName)
		}

		// Verify host goose_db_version only has the host migrations (version 0 and 100).
		var hostVersionCount int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM goose_db_version`).Scan(&hostVersionCount); err != nil {
			t.Fatalf("reading goose_db_version failed: %v", err)
		}
		if hostVersionCount != 2 {
			t.Errorf("goose_db_version should have 2 rows, got %d", hostVersionCount)
		}

		// Verify encid's migrations are recorded in encid_schema_version.
		var encidVersionCount int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM encid_schema_version`).Scan(&encidVersionCount); err != nil {
			t.Fatalf("reading encid_schema_version failed: %v", err)
		}
		if encidVersionCount == 0 {
			t.Error("encid_schema_version should have recorded migrations, got 0")
		}

		// Verify encid functionality.
		keyID, err := ks.NewKey(ctx, 1, aes.BlockSize)
		if err != nil {
			t.Fatalf("NewKey failed: %v", err)
		}
		typ, _, err := ks.DecoderByID(ctx, keyID)
		if err != nil {
			t.Fatalf("DecoderByID failed: %v", err)
		}
		if typ != 1 {
			t.Errorf("got key type %d, want 1", typ)
		}

		// Verify host can still insert / apply migrations to goose_db_version without conflict.
		_, err = db.ExecContext(ctx, `INSERT INTO goose_db_version (version_id, is_applied) VALUES (101, 1)`)
		if err != nil {
			t.Fatalf("host inserting into goose_db_version failed: %v", err)
		}
	})

	t.Run("DbutilSchemaTableNameFallback", func(t *testing.T) {
		tmpdir, err := os.MkdirTemp("", "keystore_test")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(tmpdir) // nolint:errcheck

		origTable := MigrationsTable
		origDbutilTable := dbutil.SchemaTableName
		MigrationsTable = ""
		dbutil.SchemaTableName = "dbutil_goose_version"
		t.Cleanup(func() {
			MigrationsTable = origTable
			dbutil.SchemaTableName = origDbutilTable
		})

		filename := filepath.Join(tmpdir, "keystore.db")
		db, err := sql.Open("sqlite3", filename)
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close() // nolint:errcheck

		ks, err := NewFromDB(ctx, db, false, aes.NewCipher)
		if err != nil {
			t.Fatal(err)
		}
		defer ks.Close() // nolint:errcheck

		var count int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM dbutil_goose_version`).Scan(&count); err != nil {
			t.Fatalf("dbutil_goose_version table should exist: %v", err)
		}
		if count == 0 {
			t.Error("dbutil_goose_version should have recorded migrations, got 0")
		}

		var exists int
		err = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='goose_db_version'`).Scan(&exists)
		if err != nil {
			t.Fatal(err)
		}
		if exists != 0 {
			t.Errorf("goose_db_version should not exist, found %d", exists)
		}
	})

	t.Run("FutureMigrations", func(t *testing.T) {
		for _, scenario := range []string{"fresh", "migrated", "custom_table"} {
			t.Run(scenario, func(t *testing.T) {
				tmpdir, err := os.MkdirTemp("", "keystore_test")
				if err != nil {
					t.Fatal(err)
				}
				defer os.RemoveAll(tmpdir) // nolint:errcheck

				filename := filepath.Join(tmpdir, "keystore.db")
				db, err := sql.Open("sqlite3", filename)
				if err != nil {
					t.Fatal(err)
				}
				defer db.Close() // nolint:errcheck

				var opts []goose.ProviderOption
				opts = append(opts, goose.WithVerbose(false))

				if scenario == "custom_table" {
					origTable := MigrationsTable
					MigrationsTable = "custom_goose_version"
					t.Cleanup(func() { MigrationsTable = origTable })
					opts = append(opts, goose.WithTableName("custom_goose_version"))
				} else if scenario == "migrated" {
					_, err = db.ExecContext(ctx, `
						CREATE TABLE goose_db_version (
							id INTEGER PRIMARY KEY AUTOINCREMENT,
							version_id INTEGER NOT NULL,
							is_applied INTEGER NOT NULL,
							tstamp TIMESTAMP DEFAULT (datetime('now'))
						);
						INSERT INTO goose_db_version (version_id, is_applied) VALUES (0, 1), (20231222024441, 1);
						CREATE TABLE keys (
							id INTEGER PRIMARY KEY AUTOINCREMENT,
							typ INTEGER NOT NULL,
							k BLOB NOT NULL
						);
						CREATE INDEX keys_typ_index ON keys (typ);
					`)
					if err != nil {
						t.Fatal(err)
					}
				}

				ks, err := NewFromDB(ctx, db, false, aes.NewCipher)
				if err != nil {
					t.Fatal(err)
				}
				defer ks.Close() // nolint:errcheck

				// Build a filesystem that contains the current migrations plus a future migration.
				mapFS := make(fstest.MapFS)
				mfs, err := fs.Sub(migrations, "migrations")
				if err != nil {
					t.Fatal(err)
				}
				err = fs.WalkDir(mfs, ".", func(path string, d fs.DirEntry, err error) error {
					if err != nil || d.IsDir() {
						return err
					}
					content, err := fs.ReadFile(mfs, path)
					if err != nil {
						return err
					}
					mapFS[path] = &fstest.MapFile{Data: content}
					return nil
				})
				if err != nil {
					t.Fatal(err)
				}

				mapFS["20270101000000_future.sql"] = &fstest.MapFile{
					Data: []byte("-- +goose Up\nALTER TABLE encid_keys ADD COLUMN extra TEXT;\n\n-- +goose Down\nALTER TABLE encid_keys DROP COLUMN extra;\n"),
				}

				provider, err := goose.NewProvider(goose.DialectSQLite3, db, mapFS, opts...)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := provider.Up(ctx); err != nil {
					t.Fatalf("applying future migration failed: %v", err)
				}

				// Verify column 'extra' exists on encid_keys.
				if _, err := db.ExecContext(ctx, `SELECT extra FROM encid_keys`); err != nil {
					t.Errorf("future migration was not applied: %v", err)
				}

				if scenario == "custom_table" {
					var exists int
					err = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='goose_db_version'`).Scan(&exists)
					if err != nil {
						t.Fatal(err)
					}
					if exists != 0 {
						t.Errorf("goose_db_version should not exist, found %d", exists)
					}
				}
			})
		}
	})
}
