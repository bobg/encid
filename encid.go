package encid

import (
	"context"
	"crypto/aes"
	"crypto/rand"
	"encoding/binary"
	"io"
	"strings"

	"github.com/bobg/basexx"
	"github.com/pkg/errors"
)

// KeyStore is an object that stores encryption keys.
// Each key is 16, 24, or 32 bytes long,
// and has an associated "type" (an int) and a unique key ID (an int64).
// These keys can be used to encrypt other int64s,
// and to decrypt the resulting strings.
// See EncodeID and DecodeID.
type KeyStore interface {
	// GetByID gets an encryption key and its type by the key's ID.
	// If no key with the given ID is found,
	// ErrNotFound is returned.
	GetByID(context.Context, int64) (int, []byte, error)

	// GetByType gets a key of the given type, and its ID.
	// In case there are multiple keys of the given type,
	// it is up to the implementation to choose one and return it.
	// If no key with the given type is found,
	// ErrNotFound is returned.
	GetByType(context.Context, int) (int64, []byte, error)
}

// ErrNotFound is the type of error produced when KeyStore methods find no key.
var ErrNotFound = errors.New("not found")

// EncodeID encodes a number n using a key of the given type from the given keystore.
// The result is the ID of the key used, followed by the encrypted string.
// The encrypted string is expressed in base 30,
// which uses digits 0-9, then lower-case bcdfghjkmnpqrstvwxyz.
// It excludes vowels (to avoid inadvertently spelling naughty words) and lowercase "L".
func EncodeID(ctx context.Context, ks KeyStore, typ int, n int64) (int64, string, error) {
	return encodeID(ctx, ks, typ, n, rand.Reader, basexx.Base30)
}

// EncodeID50 is the same as EncodeID but it expressed the encrypted string in base 50,
// which uses digits 0-9, then lower-case bcdfghjkmnpqrstvwxyz, then upper-case BCDFGHJKMNPQRSTVWXYZ.
func EncodeID50(ctx context.Context, ks KeyStore, typ int, n int64) (int64, string, error) {
	return encodeID(ctx, ks, typ, n, rand.Reader, basexx.Base50)
}

func encodeID(ctx context.Context, ks KeyStore, typ int, n int64, randBytes io.Reader, base basexx.Base) (int64, string, error) {
	keyID, encKey, err := ks.GetByType(ctx, typ)
	if err != nil {
		return 0, "", errors.Wrapf(err, "getting key with type %d from keystore", typ)
	}

	cipher, err := aes.NewCipher(encKey)
	if err != nil {
		return 0, "", errors.Wrapf(err, "creating cipher from key with ID %d", keyID)
	}

	var buf [aes.BlockSize]byte
	nbytes := binary.PutVarint(buf[:], n)
	_, err = io.ReadFull(randBytes, buf[nbytes:])
	if err != nil {
		return 0, "", errors.Wrap(err, "filling cipher block with random bytes")
	}

	cipher.Encrypt(buf[:], buf[:])

	var (
		src     = basexx.NewBuffer(buf[:], basexx.Binary)
		destbuf = make([]byte, basexx.Length(256, base.N(), aes.BlockSize))
		dest    = basexx.NewBuffer(destbuf, base)
	)
	nbytes, err = basexx.Convert(dest, src)
	if err != nil {
		return 0, "", errors.Wrapf(err, "converting %x to base%d", buf[:], base.N())
	}

	return keyID, string(destbuf[len(destbuf)-nbytes:]), nil
}

// DecodeID decodes a keyID/string pair produced by EncodeID.
// It produces the type of the key that was used, and the bare int64 value that was encrypted.
// As a convenience, it maps the input string to all lowercase before decoding.
func DecodeID(ctx context.Context, ks KeyStore, keyID int64, inp string) (int, int64, error) {
	return decodeID(ctx, ks, keyID, strings.ToLower(inp), basexx.Base30)
}

// DecodeID50 decodes a keyID/string pair produced by EncodeID50.
// It produces the type of the key that was used, and the bare int64 value that was encrypted.
// Unlike DecodeID, this does not map the input to lowercase first,
// since base50 strings are case-sensitive.
func DecodeID50(ctx context.Context, ks KeyStore, keyID int64, inp string) (int, int64, error) {
	return decodeID(ctx, ks, keyID, inp, basexx.Base50)
}

func decodeID(ctx context.Context, ks KeyStore, keyID int64, inp string, base basexx.Base) (int, int64, error) {
	typ, encKey, err := ks.GetByID(ctx, keyID)
	if err != nil {
		return 0, 0, errors.Wrapf(err, "getting key with ID %d", keyID)
	}

	var (
		src     = basexx.NewBuffer([]byte(inp), base)
		destbuf [aes.BlockSize]byte
		dest    = basexx.NewBuffer(destbuf[:], basexx.Binary)
	)
	_, err = basexx.Convert(dest, src)
	if err != nil {
		return 0, 0, errors.Wrapf(err, "converting %s from base%d", inp, base.N())
	}

	cipher, err := aes.NewCipher(encKey)
	if err != nil {
		return 0, 0, errors.Wrapf(err, "creating cipher from key with ID %d", keyID)
	}

	cipher.Decrypt(destbuf[:], destbuf[:])

	n, _ := binary.Varint(destbuf[:])
	return typ, n, nil
}
