package encid

import (
	"context"
	"crypto/aes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/bobg/basexx/v2"
	"github.com/pkg/errors"
)

// KeyStore is an object that stores encryption keys.
// Each key is 16, 24, or 32 bytes long,
// and has an associated "type" (an int) and a unique key ID (an int64).
// These keys can be used to encrypt other int64s,
// and to decrypt the resulting strings.
// See Encode and Decode.
type KeyStore interface {
	// DecoderByID looks up a key in the store by its ID.
	// It returns the key's type and a function for decrypting a data block using the key.
	// The slice arguments to the decryption function must overlap entirely or not at all.
	// If no key with the given ID is found,
	// ErrNotFound is returned.
	DecoderByID(context.Context, int64) (int, func(dst, src []byte), error)

	// EncoderByType looks up a key in the store by its type.
	// It returns the key's ID and a function for encrypting a data block using the key.
	// The slice arguments to the encryption function must overlap entirely or not at all.
	// In case there are multiple keys of the given type,
	// it is up to the implementation to choose one and return it.
	// If no key with the given type is found,
	// ErrNotFound is returned.
	EncoderByType(context.Context, int) (int64, func(dst, src []byte), error)
}

// ErrNotFound is the type of error produced when KeyStore methods find no key.
var ErrNotFound = errors.New("not found")

// Encode encodes a number n using a key of the given type from the given keystore.
// The result is the ID of the key used, followed by the encrypted string.
// The encrypted string is expressed in base 30,
// which uses digits 0-9, then lower-case bcdfghjkmnpqrstvwxyz.
// It excludes vowels (to avoid inadvertently spelling naughty words) and lowercase "L".
func Encode(ctx context.Context, ks KeyStore, typ int, n int64) (int64, string, error) {
	return encode(ctx, ks, typ, n, rand.Reader, basexx.Base30)
}

// Encode50 is the same as Encode but it expresses the encrypted string in base 50,
// which uses digits 0-9, then lower-case bcdfghjkmnpqrstvwxyz, then upper-case BCDFGHJKMNPQRSTVWXYZ.
func Encode50(ctx context.Context, ks KeyStore, typ int, n int64) (int64, string, error) {
	return encode(ctx, ks, typ, n, rand.Reader, basexx.Base50)
}

func encode(ctx context.Context, ks KeyStore, typ int, n int64, randBytes io.Reader, base basexx.Base) (int64, string, error) {
	keyID, enc, err := ks.EncoderByType(ctx, typ)
	if err != nil {
		return 0, "", errors.Wrapf(err, "getting key with type %d from keystore", typ)
	}

	var buf [aes.BlockSize]byte
	nbytes := binary.PutVarint(buf[:], n)
	_, err = io.ReadFull(randBytes, buf[nbytes:])
	if err != nil {
		return 0, "", errors.Wrap(err, "padding cipher block with random bytes")
	}

	enc(buf[:], buf[:])

	result, err := basexx.Convert(string(buf[:]), basexx.Binary, base)
	if err != nil {
		return 0, "", errors.Wrapf(err, "converting %x to base%d", buf[:], base.N())
	}

	return keyID, result, nil
}

// Decode decodes a keyID/string pair produced by Encode.
// It produces the type of the key that was used, and the bare int64 value that was encrypted.
// As a convenience, it maps the input string to all lowercase before decoding.
func Decode(ctx context.Context, ks KeyStore, keyID int64, inp string) (int, int64, error) {
	return decode(ctx, ks, keyID, strings.ToLower(inp), basexx.Base30)
}

// Decode50 decodes a keyID/string pair produced by Encode50.
// It produces the type of the key that was used, and the bare int64 value that was encrypted.
// Unlike Decode, this does not map the input to lowercase first,
// since base50 strings are case-sensitive.
func Decode50(ctx context.Context, ks KeyStore, keyID int64, inp string) (int, int64, error) {
	return decode(ctx, ks, keyID, inp, basexx.Base50)
}

func decode(ctx context.Context, ks KeyStore, keyID int64, inp string, base basexx.Base) (int, int64, error) {
	typ, dec, err := ks.DecoderByID(ctx, keyID)
	if err != nil {
		return 0, 0, errors.Wrapf(err, "getting key with ID %d", keyID)
	}

	bin, err := basexx.Convert(inp, base, basexx.Binary)
	if err != nil {
		return 0, 0, errors.Wrapf(err, "converting %s from base%d", inp, base.N())
	}

	if len(bin) > aes.BlockSize {
		return 0, 0, fmt.Errorf("input string too long (%d bytes)", len(bin))
	}

	var decryptBuf [aes.BlockSize]byte
	copy(decryptBuf[aes.BlockSize-len(bin):], bin)
	dec(decryptBuf[:], decryptBuf[:])

	n, _ := binary.Varint(decryptBuf[:])
	return typ, n, nil
}
