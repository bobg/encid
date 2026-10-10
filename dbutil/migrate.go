package dbutil

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"

	"github.com/bobg/errors"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/database"
)

// InitialCutoff is the migration version of the rename migration (20261006134557).
// Databases initialized from scratch skip migrations up through this version
// and start directly from the initial schema.
const InitialCutoff int64 = 20261006134557

// Migrate runs migrations for the given database.
// For databases without any encid migrations applied yet,
// it applies initSQL and records migrations up through initialCutoff as applied.
// For databases with some migrations applied, it runs pending migrations normally.
// In both cases, future migrations (versions > initialCutoff) will be run by Goose.
//
// Callers that combine an encid schema in the same database as other goose-based migrations should use [MigrateSchema] instead.
// (This function calls MigrateSchema with an empty migrationsTableName.)
func Migrate(ctx context.Context, db *sql.DB, dialect goose.Dialect, migrations fs.FS, initSQL string, initialCutoff int64) (err error) {
	return MigrateSchema(ctx, db, dialect, migrations, initSQL, initialCutoff, "")
}

// MigrateSchema runs migrations for the given database.
// For databases without any encid migrations applied yet,
// it applies initSQL and records migrations up through initialCutoff as applied.
// For databases with some migrations applied, it runs pending migrations normally.
// In both cases, future migrations (versions > initialCutoff) will be run by Goose.
//
// Migrations are recorded in the table named by migrationsTableName.
// If migrationsTableName is empty, the default goose table name is used
// ("goose_db_version").
func MigrateSchema(ctx context.Context, db *sql.DB, dialect goose.Dialect, migrations fs.FS, initSQL string, initialCutoff int64, migrationsTableName string) (err error) {
	if migrationsTableName == "" {
		migrationsTableName = goose.DefaultTablename
	}

	mfs, err := fs.Sub(migrations, "migrations")
	if err != nil {
		return errors.Wrap(err, "getting migrations")
	}

	provider, err := goose.NewProvider(dialect, db, mfs, goose.WithVerbose(false), goose.WithTableName(migrationsTableName))
	if err != nil {
		return errors.Wrap(err, "creating goose provider")
	}

	status, err := provider.Status(ctx)
	if err != nil {
		return errors.Wrap(err, "getting migration status")
	}

	var anyApplied bool
	for _, s := range status {
		if s.State == goose.StateApplied {
			anyApplied = true
			break
		}
	}

	if !anyApplied {
		if migrationsTableName != goose.DefaultTablename {
			existingSchema, err := hasExistingEncidSchema(ctx, db, dialect, status)
			if err != nil {
				return errors.Wrap(err, "checking for an existing encid schema")
			}
			if existingSchema {
				return fmt.Errorf("existing encid schema found; use its existing migrations table instead of %q", migrationsTableName)
			}
		}

		store, err := database.NewStore(dialect, migrationsTableName)
		if err != nil {
			return errors.Wrap(err, "creating goose store")
		}

		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return errors.Wrap(err, "beginning transaction for initial schema")
		}
		defer func() {
			if err != nil {
				rollbackErr := tx.Rollback()
				err = errors.Join(err, errors.Wrap(rollbackErr, "rolling back transaction"))
			}
		}()

		if _, err := tx.ExecContext(ctx, initSQL); err != nil {
			return errors.Wrap(err, "executing initial schema")
		}

		for _, s := range status {
			if s.Source.Version <= initialCutoff {
				if err := store.Insert(ctx, tx, database.InsertRequest{Version: s.Source.Version}); err != nil {
					return errors.Wrapf(err, "recording migration %d", s.Source.Version)
				}
			}
		}

		if err := tx.Commit(); err != nil {
			return errors.Wrap(err, "committing transaction")
		}
	}

	if _, err := provider.Up(ctx); err != nil {
		return errors.Wrap(err, "running migrations")
	}

	return nil
}

func hasExistingEncidSchema(ctx context.Context, db *sql.DB, dialect goose.Dialect, status []*goose.MigrationStatus) (bool, error) {
	var rows *sql.Rows
	var err error
	switch dialect {
	case goose.DialectSQLite3:
		rows, err = db.QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type = 'table' AND name IN ('keys', 'version', 'encid_keys', 'encid_version', 'goose_db_version')`)
	case goose.DialectPostgres:
		rows, err = db.QueryContext(ctx, `SELECT table_name FROM information_schema.tables WHERE table_schema = current_schema() AND table_name IN ('keys', 'version', 'encid_keys', 'encid_version', 'goose_db_version')`)
	default:
		return false, fmt.Errorf("unsupported dialect %q", dialect)
	}
	if err != nil {
		return false, err
	}
	defer rows.Close()

	tables := make(map[string]bool)
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return false, err
		}
		tables[name] = true
	}
	if err := rows.Err(); err != nil {
		return false, err
	}

	if tables["encid_keys"] || tables["encid_version"] {
		return true, nil
	}
	if (!tables["keys"] && !tables["version"]) || !tables[goose.DefaultTablename] {
		return false, nil
	}

	rows, err = db.QueryContext(ctx, `SELECT version_id, is_applied FROM goose_db_version`)
	if err != nil {
		return false, err
	}
	defer rows.Close()

	encidVersions := make(map[int64]bool, len(status))
	for _, s := range status {
		encidVersions[s.Source.Version] = true
	}
	for rows.Next() {
		var version int64
		var applied bool
		if err := rows.Scan(&version, &applied); err != nil {
			return false, err
		}
		if applied && encidVersions[version] {
			return true, nil
		}
	}
	if err := rows.Err(); err != nil {
		return false, err
	}
	return false, nil
}
