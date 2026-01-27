package token

import (
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"

	pkgtoken "github.com/heliannuuthus/helios/pkg/token"
)

// Encryptor 加密接口
type Encryptor interface {
	// Encrypt 加密数据
	Encrypt(data []byte) (string, error)
	// EncryptClaims 加密 Claims 结构
	EncryptClaims(claims *pkgtoken.Claims) (string, error)
}

// Signer 签名接口
type Signer interface {
	// Sign 签名 JWT Token
	Sign(token jwt.Token) ([]byte, error)
	// Algorithm 返回签名算法
	Algorithm() jwa.SignatureAlgorithm
}

// ========== Encryptor 实现 ==========

// JWEEncryptor 使用 JWE 加密的实现
type JWEEncryptor struct {
	key jwk.Key
}

// NewJWEEncryptor 创建 JWE 加密器
func NewJWEEncryptor(key jwk.Key) *JWEEncryptor {
	return &JWEEncryptor{key: key}
}

// NewJWEEncryptorFromBytes 从字节创建 JWE 加密器
func NewJWEEncryptorFromBytes(keyBytes []byte) (*JWEEncryptor, error) {
	key, err := jwk.Import(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("import key: %w", err)
	}
	return &JWEEncryptor{key: key}, nil
}

// Encrypt 加密数据
func (e *JWEEncryptor) Encrypt(data []byte) (string, error) {
	if e.key == nil {
		// 没有密钥则返回原始数据
		return string(data), nil
	}

	encrypted, err := jwe.Encrypt(data,
		jwe.WithKey(jwa.DIRECT(), e.key),
		jwe.WithContentEncryption(jwa.A256GCM()),
	)
	if err != nil {
		return "", fmt.Errorf("jwe encrypt: %w", err)
	}

	return string(encrypted), nil
}

// EncryptClaims 加密 Claims 结构
func (e *JWEEncryptor) EncryptClaims(claims *pkgtoken.Claims) (string, error) {
	data, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal claims: %w", err)
	}
	return e.Encrypt(data)
}

// NopEncryptor 不加密的实现（用于 ServiceAccessToken）
type NopEncryptor struct{}

// NewNopEncryptor 创建空加密器
func NewNopEncryptor() *NopEncryptor {
	return &NopEncryptor{}
}

// Encrypt 不加密，直接返回原始数据
func (e *NopEncryptor) Encrypt(data []byte) (string, error) {
	return string(data), nil
}

// EncryptClaims 不加密，直接返回 JSON
func (e *NopEncryptor) EncryptClaims(claims *pkgtoken.Claims) (string, error) {
	data, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal claims: %w", err)
	}
	return string(data), nil
}

// ========== Signer 实现 ==========

// EdDSASigner 使用 EdDSA 算法签名
type EdDSASigner struct {
	key jwk.Key
}

// NewEdDSASigner 创建 EdDSA 签名器
func NewEdDSASigner(key jwk.Key) *EdDSASigner {
	return &EdDSASigner{key: key}
}

// NewEdDSASignerFromBytes 从字节创建 EdDSA 签名器
func NewEdDSASignerFromBytes(keyBytes []byte) (*EdDSASigner, error) {
	key, err := jwk.Import(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("import key: %w", err)
	}
	return &EdDSASigner{key: key}, nil
}

// Sign 签名 JWT Token
func (s *EdDSASigner) Sign(token jwt.Token) ([]byte, error) {
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.EdDSA(), s.key))
	if err != nil {
		return nil, fmt.Errorf("sign token: %w", err)
	}
	return signed, nil
}

// Algorithm 返回签名算法
func (s *EdDSASigner) Algorithm() jwa.SignatureAlgorithm {
	return jwa.EdDSA()
}

// HMACSigner 使用 HMAC 算法签名
type HMACSigner struct {
	key jwk.Key
	alg jwa.SignatureAlgorithm
}

// NewHMACSigner 创建 HMAC 签名器
func NewHMACSigner(key jwk.Key, alg jwa.SignatureAlgorithm) *HMACSigner {
	return &HMACSigner{key: key, alg: alg}
}

// NewHS256SignerFromBytes 从字节创建 HS256 签名器
func NewHS256SignerFromBytes(keyBytes []byte) (*HMACSigner, error) {
	key, err := jwk.Import(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("import key: %w", err)
	}
	return &HMACSigner{key: key, alg: jwa.HS256()}, nil
}

// Sign 签名 JWT Token
func (s *HMACSigner) Sign(token jwt.Token) ([]byte, error) {
	signed, err := jwt.Sign(token, jwt.WithKey(s.alg, s.key))
	if err != nil {
		return nil, fmt.Errorf("sign token: %w", err)
	}
	return signed, nil
}

// Algorithm 返回签名算法
func (s *HMACSigner) Algorithm() jwa.SignatureAlgorithm {
	return s.alg
}
