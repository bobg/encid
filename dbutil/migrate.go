package dbutil

import (
	"context"
	"database/sql"
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
// (This function calls MigrateSchema with an empty migrationsTable.)
func Migrate(ctx context.Context, db *sql.DB, dialect goose.Dialect, migrations fs.FS, initSQL string, initialCutoff int64) (err error) {
	return MigrateSchema(ctx, db, dialect, migrations, initSQL, initialCutoff, "")
}

// MigrateSchema runs migrations for the given database.
// For databases without any encid migrations applied yet,
// it applies initSQL and records migrations up through initialCutoff as applied.
// For databases with some migrations applied, it runs pending migrations normally.
// In both cases, future migrations (versions > initialCutoff) will be run by Goose.
//
// Migrations are recorded in the table named by migrationsTable.
// If migrationsTable is empty, the default goose table name is used
// ("goose_db_version").
// Beware: Use a consistent value for migrationsTable!
// Changing the value of migrationsTable in a database where an encid schema already exists
// can lead to data loss.
func MigrateSchema(ctx context.Context, db *sql.DB, dialect goose.Dialect, migrations fs.FS, initSQL string, initialCutoff int64, migrationsTable string) (err error) {
	if migrationsTable == "" {
		migrationsTable = goose.DefaultTablename
	}

	mfs, err := fs.Sub(migrations, "migrations")
	if err != nil {
		return errors.Wrap(err, "getting migrations")
	}

	provider, err := goose.NewProvider(dialect, db, mfs, goose.WithVerbose(false), goose.WithTableName(migrationsTable))
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
		store, err := database.NewStore(dialect, migrationsTable)
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
