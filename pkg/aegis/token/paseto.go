package token

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"aidanwoods.dev/go-paseto"
)

// PASETO 相关错误
var (
	ErrInvalidKeyFormat = errors.New("invalid key format")
	ErrInvalidKeyType   = errors.New("invalid key type, expected Ed25519")
)

// Ed25519JWK Ed25519 JWK 格式
type Ed25519JWK struct {
	Kty string `json:"kty"`         // 密钥类型，必须是 "OKP"
	Crv string `json:"crv"`         // 曲线，必须是 "Ed25519"
	X   string `json:"x"`           // 公钥（Base64URL）
	D   string `json:"d,omitempty"` // 私钥（Base64URL，仅私钥有）
}

// ParseSecretKeyFromJWK 从 JWK JSON 字节解析 Ed25519 私钥（用于签名）
func ParseSecretKeyFromJWK(jwkBytes []byte) (paseto.V4AsymmetricSecretKey, error) {
	var jwk Ed25519JWK
	if err := json.Unmarshal(jwkBytes, &jwk); err != nil {
		return paseto.V4AsymmetricSecretKey{}, fmt.Errorf("%w: %w", ErrInvalidKeyFormat, err)
	}

	if jwk.Kty != "OKP" || jwk.Crv != "Ed25519" {
		return paseto.V4AsymmetricSecretKey{}, ErrInvalidKeyType
	}

	if jwk.D == "" {
		return paseto.V4AsymmetricSecretKey{}, fmt.Errorf("%w: missing private key (d)", ErrInvalidKeyFormat)
	}

	// 解码私钥种子
	seed, err := Base64URLDecode(jwk.D)
	if err != nil {
		return paseto.V4AsymmetricSecretKey{}, fmt.Errorf("%w: decode private key: %w", ErrInvalidKeyFormat, err)
	}

	// Ed25519 种子长度应为 32 字节
	if len(seed) != ed25519.SeedSize {
		return paseto.V4AsymmetricSecretKey{}, fmt.Errorf("%w: invalid seed size %d", ErrInvalidKeyFormat, len(seed))
	}

	// 从种子生成完整的私钥（64字节）
	privateKey := ed25519.NewKeyFromSeed(seed)

	return paseto.NewV4AsymmetricSecretKeyFromBytes(privateKey)
}

// ParsePublicKeyFromJWK 从 JWK JSON 字节解析 Ed25519 公钥（用于验证）
func ParsePublicKeyFromJWK(jwkBytes []byte) (paseto.V4AsymmetricPublicKey, error) {
	var jwk Ed25519JWK
	if err := json.Unmarshal(jwkBytes, &jwk); err != nil {
		return paseto.V4AsymmetricPublicKey{}, fmt.Errorf("%w: %w", ErrInvalidKeyFormat, err)
	}

	if jwk.Kty != "OKP" || jwk.Crv != "Ed25519" {
		return paseto.V4AsymmetricPublicKey{}, ErrInvalidKeyType
	}

	// 解码公钥
	publicKeyBytes, err := Base64URLDecode(jwk.X)
	if err != nil {
		return paseto.V4AsymmetricPublicKey{}, fmt.Errorf("%w: decode public key: %w", ErrInvalidKeyFormat, err)
	}

	if len(publicKeyBytes) != ed25519.PublicKeySize {
		return paseto.V4AsymmetricPublicKey{}, fmt.Errorf("%w: invalid public key size %d", ErrInvalidKeyFormat, len(publicKeyBytes))
	}

	return paseto.NewV4AsymmetricPublicKeyFromBytes(publicKeyBytes)
}

// PublicKeyFromSecretKey 从私钥提取公钥
func PublicKeyFromSecretKey(secretKey paseto.V4AsymmetricSecretKey) paseto.V4AsymmetricPublicKey {
	return secretKey.Public()
}

// ParseSymmetricKeyFromBytes 从原始字节解析对称密钥（用于加密 footer）
func ParseSymmetricKeyFromBytes(keyBytes []byte) (paseto.V4SymmetricKey, error) {
	if len(keyBytes) != 32 {
		return paseto.V4SymmetricKey{}, fmt.Errorf("%w: symmetric key must be 32 bytes, got %d", ErrInvalidKeyFormat, len(keyBytes))
	}
	return paseto.V4SymmetricKeyFromBytes(keyBytes)
}

// EncryptFooter 使用对称密钥加密数据（用于 footer）
func EncryptFooter(key paseto.V4SymmetricKey, data []byte) string {
	token := paseto.NewToken()
	token.SetString("data", string(data))
	return token.V4Encrypt(key, nil)
}

// DecryptFooter 使用对称密钥解密 footer
func DecryptFooter(key paseto.V4SymmetricKey, encrypted string) ([]byte, error) {
	parser := paseto.NewParser()
	token, err := parser.ParseV4Local(key, encrypted, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt footer: %w", err)
	}

	data, err := token.GetString("data")
	if err != nil {
		return nil, fmt.Errorf("get footer data: %w", err)
	}

	return []byte(data), nil
}

// BuildToken 构建 PASETO Token
func BuildToken() *paseto.Token {
	token := paseto.NewToken()
	return &token
}

// SetStandardClaims 设置标准 claims
func SetStandardClaims(token *paseto.Token, issuer string, audience string, ttl time.Duration, jti string) {
	now := time.Now()
	token.SetIssuer(issuer)
	token.SetAudience(audience)
	token.SetIssuedAt(now)
	token.SetNotBefore(now)
	token.SetExpiration(now.Add(ttl))
	token.SetJti(jti)
}

// SignToken 签名 Token
func SignToken(token *paseto.Token, secretKey paseto.V4AsymmetricSecretKey, footer []byte) string {
	var footerPtr []byte
	if len(footer) > 0 {
		footerPtr = footer
	}
	return token.V4Sign(secretKey, footerPtr)
}

// VerifyToken 验证并解析 Token
func VerifyToken(tokenString string, publicKey paseto.V4AsymmetricPublicKey) (*paseto.Token, error) {
	parser := paseto.NewParser()
	parser.AddRule(paseto.NotExpired())
	parser.AddRule(paseto.ValidAt(time.Now()))

	token, err := parser.ParseV4Public(publicKey, tokenString, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidSignature, err)
	}

	return token, nil
}

// Base64URLDecode Base64URL 解码（无填充）
func Base64URLDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}
