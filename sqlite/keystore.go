package sqlite

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"embed"
	"io/fs"

	"github.com/bobg/errors"
	_ "github.com/mattn/go-sqlite3"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/database"

	"github.com/bobg/encid/v2"
)

//go:embed init.sql
var initSQL string

//go:embed migrations/*.sql
var migrations embed.FS

const initialCutoff int64 = 20261006134557

// New creates a new SQLite-backed keystore using the given file.
// The newcipher function takes a key and returns a cipher for encrypting and decrypting.
// If newcipher is nil, it defaults to [aes.NewCipher].
//
// If the keystore is new (i.e., contains no keys),
// the version number of the keystore is set to 2.
// If the keystore is non-empty and was created before v1.5.0 of this module,
// its version will be 1.
// The version number controls whether the resulting encoded ids include a checksum.
// Version 1 ids are not compatible with version 2 ids.
//
// The caller is responsible for closing the keystore with [Close] when it is no longer needed.
func New(ctx context.Context, filename string, newcipher func([]byte) (cipher.Block, error)) (*KeyStore, error) {
	db, err := sql.Open("sqlite3", filename)
	if err != nil {
		return nil, errors.Wrapf(err, "opening %s", filename)
	}
	return NewFromDB(ctx, db, true, newcipher)
}

// NewFromDB creates a new SQLite-backed keystore using the given database connection.
// The newcipher function takes a key and returns a cipher for encrypting and decrypting.
// If newcipher is nil, it defaults to [aes.NewCipher].
//
// If the keystore is new (i.e., contains no keys),
// the version number of the keystore is set to 2.
// If the keystore is non-empty and was created before v1.5.0 of this module,
// its version will be 1.
// The version number controls whether the resulting encoded ids include a checksum.
// Version 1 ids are not compatible with version 2 ids.
//
// If own is true, then [Close] will close the underlying database connection.
// Otherwise, closing the database connection is the caller's responsibility
// and should not be done until after a call to Close.
func NewFromDB(ctx context.Context, db *sql.DB, own bool, newcipher func([]byte) (cipher.Block, error)) (*KeyStore, error) {
	if err := migrate(ctx, db); err != nil {
		return nil, errors.Wrap(err, "running migrations")
	}

	var nkeys int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM encid_keys`).Scan(&nkeys); err != nil {
		return nil, errors.Wrap(err, "counting keys")
	}
	if nkeys == 0 {
		const q = `UPDATE encid_version SET version = 2 WHERE singleton = 0 AND version < 2`
		if _, err := db.ExecContext(ctx, q); err != nil {
			return nil, errors.Wrap(err, "updating version")
		}
	}

	var version int
	if err := db.QueryRowContext(ctx, `SELECT version FROM encid_version WHERE singleton = 0`).Scan(&version); err != nil {
		return nil, errors.Wrap(err, "getting version")
	}

	if newcipher == nil {
		newcipher = aes.NewCipher
	}

	return &KeyStore{
		db:        db,
		own:       own,
		newcipher: newcipher,
		version:   version,
	}, nil
}

// Close finalizes the KeyStore, releasing resources.
// The KeyStore must not be used after calling Close.
//
// If the KeyStore "owns" the underlying database connection,
// (which is the case unless it was created via [NewFromDB] with own == false),
// Close closes the underlying database connection,
// otherwise closing the database connection is the caller's responsibility
// and should not be done until after closing the KeyStore.
func (ks *KeyStore) Close() error {
	if !ks.own {
		return nil
	}
	db := ks.db
	if db == nil {
		return nil
	}
	ks.db = nil
	return db.Close()
}

// KeyStore is an implementation of encid.KeyStore backed by a SQLite database.
type KeyStore struct {
	db        *sql.DB
	own       bool
	newcipher func([]byte) (cipher.Block, error)
	version   int
}

var _ encid.KeyStore = &KeyStore{}

func (ks *KeyStore) DecoderByID(ctx context.Context, id int64) (typ int, dec encid.Decrypter, err error) {
	const q = `SELECT typ, k FROM encid_keys WHERE id = $1`

	var k []byte

	err = ks.db.QueryRowContext(ctx, q, id).Scan(&typ, &k)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil, encid.ErrNotFound
	}
	if err != nil {
		return 0, nil, errors.Wrapf(err, "retrieving key %d", id)
	}

	ciph, err := ks.newcipher(k)
	if err != nil {
		return 0, nil, errors.Wrapf(err, "creating cipher for key %d", id)
	}

	return typ, ciph, nil
}

func (ks *KeyStore) EncoderByType(ctx context.Context, typ int) (id int64, enc encid.Encrypter, err error) {
	const q = `SELECT id, k FROM encid_keys WHERE typ = $1 ORDER BY id DESC LIMIT 1`

	var k []byte

	err = ks.db.QueryRowContext(ctx, q, typ).Scan(&id, &k)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil, encid.ErrNotFound
	}
	if err != nil {
		return 0, nil, errors.Wrapf(err, "retrieving key for type %d", typ)
	}

	ciph, err := ks.newcipher(k)
	if err != nil {
		return 0, nil, errors.Wrapf(err, "creating cipher for key %d", id)
	}

	return id, ciph, nil
}

func (ks *KeyStore) Version() int {
	return ks.version
}

func (ks *KeyStore) NewKey(ctx context.Context, typ, keysize int) (int64, error) {
	k := make([]byte, keysize)
	if _, err := rand.Read(k); err != nil {
		return 0, errors.Wrap(err, "generating key")
	}

	const q = `INSERT INTO encid_keys (typ, k) VALUES ($1, $2)`

	res, err := ks.db.ExecContext(ctx, q, typ, k)
	if err != nil {
		return 0, errors.Wrap(err, "inserting key")
	}

	return res.LastInsertId()
}

func migrate(ctx context.Context, db *sql.DB) error {
	mfs, err := fs.Sub(migrations, "migrations")
	if err != nil {
		return errors.Wrap(err, "getting migrations")
	}

	provider, err := goose.NewProvider(goose.DialectSQLite3, db, mfs, goose.WithVerbose(false))
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
		store, err := database.NewStore(goose.DialectSQLite3, goose.DefaultTablename)
		if err != nil {
			return errors.Wrap(err, "creating goose store")
		}

		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return errors.Wrap(err, "beginning transaction for initial schema")
		}
		defer tx.Rollback()

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
