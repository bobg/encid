package sqlite

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"embed"

	"github.com/bobg/errors"
	_ "github.com/mattn/go-sqlite3"
	"github.com/pressly/goose/v3"

	"github.com/bobg/encid/v2"
	"github.com/bobg/encid/v2/dbutil"
)

//go:embed init.sql
var initSQL string

//go:embed migrations/*.sql
var migrations embed.FS

const initialCutoff = dbutil.InitialCutoff

// New creates a new SQLite-backed keystore using the given file.
//
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
	return NewSchema(ctx, filename, "", newcipher)
}

// NewSchema creates a new SQLite-backed keystore using the given file.
//
// The newcipher function takes a key and returns a cipher for encrypting and decrypting.
// If newcipher is nil, it defaults to [aes.NewCipher].
//
// If migrationsTable is non-empty, it is used as the name of the table used to record applied schema migrations.
// When empty, the default goose table name is used ("goose_db_version").
// Callers wishing to combine an encid schema in the same database as other goose-based migrations
// should set this to a non-empty value to avoid conflicts.
// Beware: Use a consistent value for migrationsTable!
// Changing the value of migrationsTable in a database where an encid schema already exists
// can lead to data loss.
//
// If the keystore is new (i.e., contains no keys),
// the version number of the keystore is set to 2.
// If the keystore is non-empty and was created before v1.5.0 of this module,
// its version will be 1.
// The version number controls whether the resulting encoded ids include a checksum.
// Version 1 ids are not compatible with version 2 ids.
//
// The caller is responsible for closing the keystore with [Close] when it is no longer needed.
func NewSchema(ctx context.Context, filename, migrationsTable string, newcipher func([]byte) (cipher.Block, error)) (*KeyStore, error) {
	db, err := sql.Open("sqlite3", filename)
	if err != nil {
		return nil, errors.Wrapf(err, "opening %s", filename)
	}
	return NewSchemaFromDB(ctx, db, migrationsTable, true, newcipher)
}

// NewFromDB creates a new SQLite-backed keystore using the given database connection.
//
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
	return NewSchemaFromDB(ctx, db, "", own, newcipher)
}

// NewSchemaFromDB creates a new SQLite-backed keystore using the given database connection.
//
// The newcipher function takes a key and returns a cipher for encrypting and decrypting.
// If newcipher is nil, it defaults to [aes.NewCipher].
//
// If migrationsTable is non-empty, it is used as the name of the table used to record applied schema migrations.
// When empty, the default goose table name is used ("goose_db_version").
// Callers wishing to combine an encid schema in the same database as other goose-based migrations
// should set this to a non-empty value to avoid conflicts.
// Beware: Use a consistent value for migrationsTable!
// Changing the value of migrationsTable in a database where an encid schema already exists
// can lead to data loss.
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
func NewSchemaFromDB(ctx context.Context, db *sql.DB, migrationsTable string, own bool, newcipher func([]byte) (cipher.Block, error)) (*KeyStore, error) {
	if err := dbutil.MigrateSchema(ctx, db, goose.DialectSQLite3, migrations, initSQL, initialCutoff, migrationsTable); err != nil {
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
// (which is the case unless it was created via [NewFromDB] or [NewSchemaFromDB] with own == false),
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
