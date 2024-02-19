package encid

import (
	"context"
	"crypto/aes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"hash/crc32"
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
// See Encode and Decode.
//
// If you're implementing a KeyStore,
// you should also implement the [Versioner] interface,
// and return a value of 2 or greater from the Version method.
// A KeyStore that isn't also a Versioner is assumed to be at version 1.
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

// Versioner is an optional interface that KeyStores should implement.
// It reports the version of the encoding to use when using a KeyStore.
// When the KeyStore is a Versioner reporting version 2 or later,
// [Encode] and [Encode50] produce encoded ids that include a checksum
// and [Decode] and [Decode50] verify that checksum.
// See https://github.com/bobg/encid/issues/5.
//
// If a KeyStore does not implement Versioner, it is assumed to be at version 1.
//
// Version 2 encoded IDs are not compatible with version 1 IDs;
// you can't decode a v2 ID using a v1 KeyStore and vice versa.
type Versioner interface {
	Version() int
}

var (
	// ErrNotFound is the type of error produced when KeyStore methods find no key.
	ErrNotFound = errors.New("not found")

	// ErrChecksum is the type of error produced when a checksum fails during decoding.
	ErrChecksum = errors.New("checksum failed")
)

// Encode encodes a number n using a key of the given type from the given keystore.
// The result is the ID of the key used, followed by the encrypted string.
// The encrypted string is expressed in base 30,
// which uses digits 0-9, then lower-case bcdfghjkmnpqrstvwxyz.
// It excludes vowels (to avoid inadvertently spelling naughty words) and lowercase "L".
//
// If the keystore is also a [Versioner] that reports a version of 2 or greater,
// the resulting string will include a checksum that is checked at decoding time.
// See https://github.com/bobg/encid/issues/5.
func Encode(ctx context.Context, ks KeyStore, typ int, n int64) (int64, string, error) {
	return encode(ctx, ks, typ, n, rand.Reader, basexx.Base30)
}

// Encode50 is the same as Encode but it expresses the encrypted string in base 50,
// which uses digits 0-9, then lower-case bcdfghjkmnpqrstvwxyz, then upper-case BCDFGHJKMNPQRSTVWXYZ.
//
// If the keystore is also a [Versioner] that reports a version of 2 or greater,
// the resulting string will include a checksum that is checked at decoding time.
// See https://github.com/bobg/encid/issues/5.
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

	// Nbytes is between 1 and 10, inclusive,
	// and aes.BlockSize is 16.
	// For version 2 keystores and later,
	// let's put a 32-bit checksum in the last four bytes.
	// The rest gets filled with randomness.

	versioner, isV2 := ks.(Versioner)
	isV2 = isV2 && versioner.Version() >= 2

	randbuf := buf[nbytes:]
	if isV2 {
		randbuf = buf[nbytes : len(buf)-4]
	}

	_, err = io.ReadFull(randBytes, randbuf)
	if err != nil {
		return 0, "", errors.Wrap(err, "padding cipher block with random bytes")
	}

	if isV2 {
		checksum := crc32.ChecksumIEEE(buf[:len(buf)-4])
		binary.LittleEndian.PutUint32(buf[len(buf)-4:], checksum)
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
//
// If the keystore is also a [Versioner] that reports a version of 2 or greater,
// the input string must include a checksum and may result an ErrChecksum error in case of a mismatch.
// See https://github.com/bobg/encid/issues/5.
func Decode(ctx context.Context, ks KeyStore, keyID int64, inp string) (int, int64, error) {
	return decode(ctx, ks, keyID, strings.ToLower(inp), basexx.Base30)
}

// Decode50 decodes a keyID/string pair produced by Encode50.
// It produces the type of the key that was used, and the bare int64 value that was encrypted.
// Unlike Decode, this does not map the input to lowercase first,
// since base50 strings are case-sensitive.
//
// If the keystore is also a [Versioner] that reports a version of 2 or greater,
// the input string must include a checksum and may result an ErrChecksum error in case of a mismatch.
// See https://github.com/bobg/encid/issues/5.
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

	if v, ok := ks.(Versioner); ok && v.Version() >= 2 {
		// For version 2 keystores and later,
		// the last four bytes are a checksum that we must verify.

		var (
			received = binary.LittleEndian.Uint32(decryptBuf[len(decryptBuf)-4:])
			computed = crc32.ChecksumIEEE(decryptBuf[:len(decryptBuf)-4])
		)
		if computed != received {
			return 0, 0, ErrChecksum
		}
	}

	n, x := binary.Varint(decryptBuf[:])
	if x <= 0 {
		return 0, 0, fmt.Errorf("decoding error")
	}
	return typ, n, nil
}
