package encid

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/bobg/basexx/v2"
	"github.com/bobg/errors"
)

// KeyStore is an object that stores encryption keys.
// Each key is 16, 24, or 32 bytes long,
// and has an associated "type" (an int) and a unique key ID (an int64).
// These keys can be used to encrypt other int64s,
// and to decrypt the resulting strings.
// See [Encode] and [Decode].
//
// The meanings of the "type" values are user-defined.
// You may choose to give all your keys the same type,
// or you might prefer to use different types for different resources
// (e.g. 1 for users, 2 for documents, etc).
type KeyStore interface {
	// DecoderByID looks up a key in the store by its ID.
	// It returns the key's type and a [Decrypter] for decrypting a data block using the key.
	// If no key with the given ID is found,
	// ErrNotFound is returned.
	DecoderByID(context.Context, int64) (int, Decrypter, error)

	// EncoderByType looks up a key in the store by its type.
	// It returns the key's ID and an [Encrypter] for encrypting a data block using the key.
	// In case there are multiple keys of the given type,
	// it is up to the implementation to choose one and return it.
	// (For example, it could choose the newest one.)
	// If no key with the given type is found,
	// ErrNotFound is returned.
	EncoderByType(context.Context, int) (int64, Encrypter, error)

	// Version reports the highest encoded-data format produced and understood by the KeyStore.
	// It should return the number 2.
	// (Earlier versions of this module didn’t include this method,
	// and are considered to be at format version 1.
	// Future versions may introduce new formats.)
	Version() int
}

// Decrypter is the type of an object that can decrypt a block of data.
// Note: this interface is satisfied by the Block type in crypto/cipher.
type Decrypter interface {
	// BlockSize returns the Decrypter’s block size.
	BlockSize() int

	// Decrypt decrypts the first block in src into dst.
	// Dst and src must overlap entirely or not at all.
	Decrypt(dst, src []byte)
}

// Encrypter is the type of an object that can encrypt a block of data.
// Note: this interface is satisfied by the Block type in crypto/cipher.
type Encrypter interface {
	// BlockSize returns the Encrypter’s block size.
	BlockSize() int

	// Encrypt encrypts the first block in src into dst.
	// Dst and src must overlap entirely or not at all.
	Encrypt(dst, src []byte)
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

// Encode50 is the same as [Encode] but it expresses the encrypted string in base 50,
// which uses digits 0-9, then lower-case bcdfghjkmnpqrstvwxyz, then upper-case BCDFGHJKMNPQRSTVWXYZ.
func Encode50(ctx context.Context, ks KeyStore, typ int, n int64) (int64, string, error) {
	return encode(ctx, ks, typ, n, rand.Reader, basexx.Base50)
}

// EncodeXX is the same as [Encode] but permits using any number base.
func EncodeXX(ctx context.Context, ks KeyStore, typ int, n int64, base basexx.Base) (int64, string, error) {
	return encode(ctx, ks, typ, n, rand.Reader, base)
}

func encode(ctx context.Context, ks KeyStore, typ int, n int64, randBytes io.Reader, base basexx.Base) (int64, string, error) {
	keyID, enc, err := ks.EncoderByType(ctx, typ)
	if err != nil {
		return 0, "", errors.Wrapf(err, "getting key with type %d from keystore", typ)
	}

	buf := make([]byte, enc.BlockSize())

	if ks.Version() >= 2 {
		buf[0] = 2 // Version byte.
		binary.LittleEndian.PutUint64(buf[1:], uint64(n))
	} else {
		nbytes := binary.PutVarint(buf[:], n)
		_, err = io.ReadFull(randBytes, buf[nbytes:])
		if err != nil {
			return 0, "", errors.Wrap(err, "padding cipher block with random bytes")
		}
	}

	enc.Encrypt(buf[:], buf[:])

	result, err := basexx.Convert(string(buf[:]), basexx.Binary, base)
	if err != nil {
		return 0, "", errors.Wrapf(err, "converting %x to base%d", buf[:], base.N())
	}

	return keyID, result, nil
}

// Decode decodes a keyID/string pair produced by [Encode].
// It produces the type of the key that was used, and the bare int64 value that was encrypted.
// As a convenience, it maps the input string to all lowercase before decoding.
func Decode(ctx context.Context, ks KeyStore, keyID int64, inp string) (int, int64, error) {
	return decode(ctx, ks, keyID, strings.ToLower(inp), basexx.Base30)
}

// Decode50 decodes a keyID/string pair produced by [Encode50].
// It produces the type of the key that was used, and the bare int64 value that was encrypted.
// Unlike [Decode], this does not map the input to lowercase first,
// since base50 strings are case-sensitive.
func Decode50(ctx context.Context, ks KeyStore, keyID int64, inp string) (int, int64, error) {
	return decode(ctx, ks, keyID, inp, basexx.Base50)
}

// DecodeXX decodes a keyID/string pair produced by [EncodeXX] using the given base.
func DecodeXX(ctx context.Context, ks KeyStore, keyID int64, inp string, base basexx.Base) (int, int64, error) {
	return decode(ctx, ks, keyID, inp, base)
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

	if len(bin) > dec.BlockSize() {
		return 0, 0, fmt.Errorf("input string too long (%d bytes)", len(bin))
	}

	var (
		blockSize  = dec.BlockSize()
		decryptBuf = make([]byte, blockSize)
	)
	copy(decryptBuf[blockSize-len(bin):], bin)
	dec.Decrypt(decryptBuf[:], decryptBuf[:])

	if ks.Version() >= 2 {
		// For version 2 keystores and later,
		// check the version byte,
		// and that the buffer is zero-padded.
		// See https://github.com/bobg/encid/issues/5.

		if decryptBuf[0] != 2 {
			return 0, 0, fmt.Errorf("unexpected version byte %d", decryptBuf[0])
		}

		zeroes := make([]byte, blockSize-9)
		if !bytes.Equal(decryptBuf[9:], zeroes) {
			return 0, 0, fmt.Errorf("zero-padding check failed")
		}

		n := int64(binary.LittleEndian.Uint64(decryptBuf[1:]))

		return typ, n, nil
	}

	n, x := binary.Varint(decryptBuf[:])
	if x <= 0 {
		return 0, 0, fmt.Errorf("decoding error")
	}
	return typ, n, nil
}
