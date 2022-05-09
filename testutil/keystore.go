package testutil

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
)

type KeyStore struct {
	NumTypes int
}

func (tks *KeyStore) cipherByID(keyID int64) (cipher.Block, error) {
	var buf [16]byte
	binary.BigEndian.PutUint32(buf[:], uint32(keyID))
	return aes.NewCipher(buf[:])
}

func (tks *KeyStore) DecoderByID(_ context.Context, keyID int64) (int, func(dst, src []byte), error) {
	n := tks.NumTypes
	if n < 1 {
		n = 2
	}
	ciph, err := tks.cipherByID(keyID)
	if err != nil {
		return 0, nil, err
	}
	return int(keyID) % n, ciph.Decrypt, err
}

func (tks *KeyStore) EncoderByType(ctx context.Context, typ int) (int64, func(dst, src []byte), error) {
	id := int64(typ)
	ciph, err := tks.cipherByID(id)
	if err != nil {
		return 0, nil, err
	}
	return id, ciph.Encrypt, err
}
