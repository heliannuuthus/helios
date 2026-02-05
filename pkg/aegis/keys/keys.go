// Package keys 提供密钥派生、解析和提供者功能
package keys

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
	ErrInvalidKeyFormat = errors.New("invalid key format")
	ErrKeyNotFound      = errors.New("key not found")
)

// KDF 密钥用途标识（作为 Argon2id 的 salt）
const (
	KDFSaltEncrypt = "aegis:encrypt" // 用于加密
	KDFSaltSign    = "aegis:sign"    // 用于签名
)

// Argon2id 参数
const (
	Argon2Time    = 1
	Argon2Memory  = 64 * 1024 // 64 MB
	Argon2Threads = 4
	Argon2KeyLen  = 32
)

// ==================== 密钥派生（经过 KDF）====================

// DeriveKey 使用 Argon2id 从主密钥派生子密钥
// masterKey: 32 字节主密钥（seed）
// salt: 密钥用途标识（如 KDFSaltEncrypt, KDFSaltSign）
// 返回 32 字节派生密钥
func DeriveKey(masterKey []byte, salt string) ([]byte, error) {
	if len(masterKey) != 32 {
		return nil, fmt.Errorf("%w: master key must be 32 bytes, got %d", ErrInvalidKeyFormat, len(masterKey))
	}

	// Argon2id 派生
	derivedKey := argon2.IDKey(masterKey, []byte(salt), Argon2Time, Argon2Memory, Argon2Threads, Argon2KeyLen)
	return derivedKey, nil
}

// DeriveSymmetricKey 从 32 字节主密钥派生加密用对称密钥
func DeriveSymmetricKey(masterKey []byte) (paseto.V4SymmetricKey, error) {
	derivedKey, err := DeriveKey(masterKey, KDFSaltEncrypt)
	if err != nil {
		return paseto.V4SymmetricKey{}, err
	}
	return paseto.V4SymmetricKeyFromBytes(derivedKey)
}

// DeriveSecretKey 从 32 字节主密钥派生签名用 Ed25519 私钥
func DeriveSecretKey(masterKey []byte) (paseto.V4AsymmetricSecretKey, error) {
	derivedSeed, err := DeriveKey(masterKey, KDFSaltSign)
	if err != nil {
		return paseto.V4AsymmetricSecretKey{}, err
	}
	// 从派生种子生成 Ed25519 私钥
	privateKey := ed25519.NewKeyFromSeed(derivedSeed)
	return paseto.NewV4AsymmetricSecretKeyFromBytes(privateKey)
}

// DerivePublicKey 从 32 字节主密钥派生 Ed25519 公钥
func DerivePublicKey(masterKey []byte) (paseto.V4AsymmetricPublicKey, error) {
	secretKey, err := DeriveSecretKey(masterKey)
	if err != nil {
		return paseto.V4AsymmetricPublicKey{}, err
	}
	return secretKey.Public(), nil
}

// ==================== 密钥解析（从 32 字节 seed，不经过 KDF）====================

// ParseSecretKeyFromSeed 从 32 字节 seed 直接生成 Ed25519 私钥（不经过 KDF）
func ParseSecretKeyFromSeed(seed []byte) (paseto.V4AsymmetricSecretKey, error) {
	if len(seed) != 32 {
		return paseto.V4AsymmetricSecretKey{}, fmt.Errorf("%w: seed must be 32 bytes, got %d", ErrInvalidKeyFormat, len(seed))
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	return paseto.NewV4AsymmetricSecretKeyFromBytes(privateKey)
}

// ParsePublicKeyFromSeed 从 32 字节 seed 直接生成 Ed25519 公钥（不经过 KDF）
func ParsePublicKeyFromSeed(seed []byte) (paseto.V4AsymmetricPublicKey, error) {
	secretKey, err := ParseSecretKeyFromSeed(seed)
	if err != nil {
		return paseto.V4AsymmetricPublicKey{}, err
	}
	return secretKey.Public(), nil
}

// ParseSymmetricKeyFromBytes 从原始字节解析对称密钥
func ParseSymmetricKeyFromBytes(keyBytes []byte) (paseto.V4SymmetricKey, error) {
	if len(keyBytes) != 32 {
		return paseto.V4SymmetricKey{}, fmt.Errorf("%w: symmetric key must be 32 bytes, got %d", ErrInvalidKeyFormat, len(keyBytes))
	}
	return paseto.V4SymmetricKeyFromBytes(keyBytes)
}

// ==================== 公钥导出 ====================

// PublicKeyFromSecretKey 从私钥提取公钥
func PublicKeyFromSecretKey(secretKey paseto.V4AsymmetricSecretKey) paseto.V4AsymmetricPublicKey {
	return secretKey.Public()
}

// ExportPublicKeyBase64 导出公钥为 Base64 标准编码
func ExportPublicKeyBase64(publicKey paseto.V4AsymmetricPublicKey) string {
	return base64.StdEncoding.EncodeToString(publicKey.ExportBytes())
}
