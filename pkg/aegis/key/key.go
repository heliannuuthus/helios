package key

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"

	"aidanwoods.dev/go-paseto"
	"golang.org/x/crypto/argon2"
)

// 错误定义
var (
	ErrInvalidFormat = errors.New("invalid key format")
	ErrNotFound      = errors.New("key not found")
)

// Seed 结构：48 字节
// - 前 16 字节：salt（用于 KDF）
// - 后 32 字节：key material（主密钥）
const (
	SeedLength     = 48
	SeedSaltLength = 16
	SeedKeyLength  = 32
	SeedSaltOffset = 0
	SeedKeyOffset  = SeedSaltLength
)

// KDF 用途标识
const (
	PurposeEncrypt = "encrypt"
	PurposeSign    = "sign"
)

// Argon2id 参数
const (
	argon2Time    = 1
	argon2Memory  = 64 * 1024 // 64 MB
	argon2Threads = 4
	argon2KeyLen  = 32
)

// Seed 表示 48 字节的种子密钥
type Seed []byte

// ParseSeed 解析并验证 seed
func ParseSeed(data []byte) (Seed, error) {
	if len(data) != SeedLength {
		return nil, fmt.Errorf("%w: seed must be %d bytes, got %d", ErrInvalidFormat, SeedLength, len(data))
	}
	return Seed(data), nil
}

// Salt 返回 salt 部分（前 16 字节）
func (s Seed) Salt() []byte {
	return s[SeedSaltOffset:SeedSaltLength]
}

// Key 返回 key material 部分（后 32 字节）
func (s Seed) Key() []byte {
	return s[SeedKeyOffset:]
}

// Derive 使用 Argon2id 派生子密钥
func (s Seed) Derive(purpose string) []byte {
	salt := append(s.Salt(), []byte(purpose)...)
	return argon2.IDKey(s.Key(), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
}

// DeriveSymmetricKey 派生加密用对称密钥
func (s Seed) DeriveSymmetricKey() (paseto.V4SymmetricKey, error) {
	return paseto.V4SymmetricKeyFromBytes(s.Derive(PurposeEncrypt))
}

// DeriveSecretKey 派生签名用 Ed25519 私钥
func (s Seed) DeriveSecretKey() (paseto.V4AsymmetricSecretKey, error) {
	privateKey := ed25519.NewKeyFromSeed(s.Derive(PurposeSign))
	return paseto.NewV4AsymmetricSecretKeyFromBytes(privateKey)
}

// DerivePublicKey 派生 Ed25519 公钥
func (s Seed) DerivePublicKey() (paseto.V4AsymmetricPublicKey, error) {
	secretKey, err := s.DeriveSecretKey()
	if err != nil {
		return paseto.V4AsymmetricPublicKey{}, err
	}
	return secretKey.Public(), nil
}

// ExportPublicKeyBase64 导出公钥为 Base64 标准编码
func ExportPublicKeyBase64(publicKey paseto.V4AsymmetricPublicKey) string {
	return base64.StdEncoding.EncodeToString(publicKey.ExportBytes())
}
