package utils

import (
	"fmt"
	"time"

	"github.com/heliannuuthus/helios/pkg/json"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// UserClaims 用户信息结构（用于加密/解密 sub）
type UserClaims struct {
	OpenID   string `json:"openid,omitempty"`
	Nickname string `json:"nickname,omitempty"`
	Picture  string `json:"picture,omitempty"`
	Email    string `json:"email,omitempty"`
	Phone    string `json:"phone,omitempty"`
}

// ExtractedClaims JWT 提取的基本信息（不验证签名）
type ExtractedClaims struct {
	Issuer    string    `json:"iss,omitempty"`
	Subject   string    `json:"sub,omitempty"`
	Audience  []string  `json:"aud,omitempty"`
	ExpiresAt time.Time `json:"exp,omitempty"`
	IssuedAt  time.Time `json:"iat,omitempty"`
	NotBefore time.Time `json:"nbf,omitempty"`
	JwtID     string    `json:"jti,omitempty"`
	ClientID  string    `json:"cli,omitempty"` // 自定义字段
	Scope     string    `json:"scope,omitempty"`
}

// ExtractClaims 从 JWT 提取 claims（不验证签名）
// 用于在验证前获取 token 中的关键信息（如 aud, cli）以获取正确的密钥
func ExtractClaims(tokenString string) (*ExtractedClaims, error) {
	token, err := jwt.Parse([]byte(tokenString), jwt.WithVerify(false))
	if err != nil {
		return nil, fmt.Errorf("parse token: %w", err)
	}

	claims := &ExtractedClaims{}

	// 标准字段
	if iss, ok := token.Issuer(); ok {
		claims.Issuer = iss
	}
	if sub, ok := token.Subject(); ok {
		claims.Subject = sub
	}
	if aud, ok := token.Audience(); ok {
		claims.Audience = aud
	}
	if exp, ok := token.Expiration(); ok {
		claims.ExpiresAt = exp
	}
	if iat, ok := token.IssuedAt(); ok {
		claims.IssuedAt = iat
	}
	if nbf, ok := token.NotBefore(); ok {
		claims.NotBefore = nbf
	}
	if jti, ok := token.JwtID(); ok {
		claims.JwtID = jti
	}

	// 自定义字段
	var cli string
	if err := token.Get("cli", &cli); err == nil {
		claims.ClientID = cli
	}
	var scope string
	if err := token.Get("scope", &scope); err == nil {
		claims.Scope = scope
	}

	return claims, nil
}

// GetAudience 从 token 提取 audience（不验证）
func GetAudience(tokenString string) (string, error) {
	claims, err := ExtractClaims(tokenString)
	if err != nil {
		return "", err
	}
	if len(claims.Audience) == 0 {
		return "", fmt.Errorf("missing audience")
	}
	return claims.Audience[0], nil
}

// GetClientID 从 token 提取 client_id（不验证）
func GetClientID(tokenString string) (string, error) {
	claims, err := ExtractClaims(tokenString)
	if err != nil {
		return "", err
	}
	if claims.ClientID == "" {
		return "", fmt.Errorf("missing client_id")
	}
	return claims.ClientID, nil
}

// DecryptUserClaims 使用指定密钥解密用户信息
func DecryptUserClaims(encryptedSub string, decryptKey jwk.Key) (*UserClaims, error) {
	var data []byte

	if decryptKey == nil {
		// 没有解密密钥则直接解析 JSON
		data = []byte(encryptedSub)
	} else {
		decrypted, err := jwe.Decrypt([]byte(encryptedSub),
			jwe.WithKey(jwa.DIRECT(), decryptKey),
		)
		if err != nil {
			return nil, err
		}
		data = decrypted
	}

	var claims UserClaims
	if err := json.Unmarshal(data, &claims); err != nil {
		return nil, err
	}

	return &claims, nil
}

// EncryptUserClaims 加密用户信息为 JWE
func EncryptUserClaims(claims *UserClaims, encryptKey jwk.Key) (string, error) {
	plaintext, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	encrypted, err := jwe.Encrypt(plaintext,
		jwe.WithKey(jwa.DIRECT(), encryptKey),
		jwe.WithContentEncryption(jwa.A256GCM()),
	)
	if err != nil {
		return "", err
	}

	return string(encrypted), nil
}

// VerifyToken 验证 JWT 签名
func VerifyToken(tokenString string, publicKey jwk.Key, algorithm jwa.SignatureAlgorithm) (jwt.Token, error) {
	return jwt.Parse([]byte(tokenString),
		jwt.WithKey(algorithm, publicKey),
		jwt.WithValidate(true),
	)
}

// SignToken 签名 JWT
func SignToken(token jwt.Token, privateKey jwk.Key, algorithm jwa.SignatureAlgorithm) ([]byte, error) {
	return jwt.Sign(token, jwt.WithKey(algorithm, privateKey))
}
