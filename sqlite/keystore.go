package sqlite

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"embed"
	"io/fs"
	"os"

	"github.com/bobg/errors"
	_ "github.com/mattn/go-sqlite3"
	"github.com/pressly/goose/v3"

	"github.com/bobg/encid"
)

//go:embed migrations/*.sql
var migrations embed.FS

// New creates a new SQLite-backed keystore using the given file.
// If the file does not exist, it is created and the version number of the keystore is set to 2.
// The newcipher function takes a key and returns a cipher for encrypting and decrypting.
func New(ctx context.Context, filename string, newcipher func([]byte) (cipher.Block, error)) (*KeyStore, error) {
	_, err := os.Stat(filename)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, errors.Wrapf(err, "checking for %s", filename)
	}
	existed := err == nil

	db, err := sql.Open("sqlite3", filename)
	if err != nil {
		return nil, errors.Wrapf(err, "opening %s", filename)
	}

	mfs, err := fs.Sub(migrations, "migrations")
	if err != nil {
		return nil, errors.Wrap(err, "getting migrations")
	}

	provider, err := goose.NewProvider(goose.DialectSQLite3, db, mfs, goose.WithVerbose(false))
	if err != nil {
		return nil, errors.Wrap(err, "creating goose provider")
	}
	if _, err := provider.Up(ctx); err != nil {
		return nil, errors.Wrap(err, "running migrations")
	}

	if !existed {
		const q = `UPDATE version SET version = 2 WHERE singleton = 0 AND version < 2`
		_, err := db.ExecContext(ctx, q)
		if err != nil {
			return nil, errors.Wrap(err, "updating version")
		}
	}

	var version int
	err = db.QueryRowContext(ctx, `SELECT version FROM version WHERE singleton = 0`).Scan(&version)
	if err != nil {
		return nil, errors.Wrap(err, "getting version")
	}

	return &KeyStore{
		db:        db,
		newcipher: newcipher,
		version:   version,
	}, nil
}

// KeyStore is an implementation of encid.KeyStore backed by a SQLite database.
type KeyStore struct {
	db        *sql.DB
	newcipher func([]byte) (cipher.Block, error)
	version   int
}

var _ encid.KeyStore = &KeyStore{}

func (ks *KeyStore) DecoderByID(ctx context.Context, id int64) (typ int, dec func(dst, src []byte), err error) {
	const q = `SELECT typ, k FROM keys WHERE id = $1`

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

	return typ, ciph.Decrypt, nil
}

func (ks *KeyStore) EncoderByType(ctx context.Context, typ int) (id int64, enc func(dst, src []byte), err error) {
	const q = `SELECT id, k FROM keys WHERE typ = $1 ORDER BY id DESC LIMIT 1`

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

	return id, ciph.Encrypt, nil
}

func (ks *KeyStore) Version() int {
	return ks.version
}

func (ks *KeyStore) NewKey(ctx context.Context, typ, keysize int) (int64, error) {
	k := make([]byte, keysize)
	if _, err := rand.Read(k); err != nil {
		return 0, errors.Wrap(err, "generating key")
	}

	const q = `INSERT INTO keys (typ, k) VALUES ($1, $2)`

	res, err := ks.db.ExecContext(ctx, q, typ, k)
	if err != nil {
		return 0, errors.Wrap(err, "inserting key")
	}

	return res.LastInsertId()
}
