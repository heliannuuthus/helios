package paseto

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"

	gopaseto "aidanwoods.dev/go-paseto"
	"golang.org/x/crypto/argon2"
)

var (
	ErrInvalidFormat = errors.New("invalid key format")
	ErrDecryptFailed = errors.New("decrypt failed")
)

const (
	SeedLength     = 48
	SeedSaltLength = 16
	SeedKeyLength  = 32
	SeedSaltOffset = 0
	SeedKeyOffset  = SeedSaltLength
)

const (
	PurposeEncrypt = "encrypt"
	PurposeSign    = "sign"
)

const (
	argon2Time    = 1
	argon2Memory  = 64 * 1024 // 64 MB
	argon2Threads = 4
	argon2KeyLen  = 32
)

// Seed 表示 48 字节的种子密钥。
// 前 16 字节为 salt（用于 KDF），后 32 字节为 key material（主密钥）。
type Seed []byte

func ParseSeed(data []byte) (Seed, error) {
	if len(data) != SeedLength {
		return nil, fmt.Errorf("%w: seed must be %d bytes, got %d", ErrInvalidFormat, SeedLength, len(data))
	}
	return Seed(data), nil
}

func (s Seed) Salt() []byte {
	return s[SeedSaltOffset:SeedSaltLength]
}

func (s Seed) Key() []byte {
	return s[SeedKeyOffset:]
}

// Derive 使用 Argon2id 派生子密钥
func (s Seed) Derive(purpose string) []byte {
	raw := s.Salt()
	salt := make([]byte, len(raw), len(raw)+len(purpose))
	copy(salt, raw)
	salt = append(salt, []byte(purpose)...)
	return argon2.IDKey(s.Key(), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
}

func (s Seed) DeriveSymmetricKey() (gopaseto.V4SymmetricKey, error) {
	return gopaseto.V4SymmetricKeyFromBytes(s.Derive(PurposeEncrypt))
}

func (s Seed) DeriveSecretKey() (gopaseto.V4AsymmetricSecretKey, error) {
	privateKey := ed25519.NewKeyFromSeed(s.Derive(PurposeSign))
	return gopaseto.NewV4AsymmetricSecretKeyFromBytes(privateKey)
}

func (s Seed) DerivePublicKey() (gopaseto.V4AsymmetricPublicKey, error) {
	secretKey, err := s.DeriveSecretKey()
	if err != nil {
		return gopaseto.V4AsymmetricPublicKey{}, err
	}
	return secretKey.Public(), nil
}

func ExportPublicKeyBase64(publicKey gopaseto.V4AsymmetricPublicKey) string {
	return base64.StdEncoding.EncodeToString(publicKey.ExportBytes())
}
