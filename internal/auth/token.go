package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/heliannuuthus/helios/internal/config"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// TokenManager Token 管理器
type TokenManager struct {
	issuer     string
	signingKey jwk.Key
	encryptKey jwk.Key
}

// NewTokenManager 创建 Token 管理器
func NewTokenManager() (*TokenManager, error) {
	tm := &TokenManager{
		issuer: config.GetString("auth.issuer"),
	}

	// 加载签名密钥
	signKeyB64 := config.GetString("kms.token.sign-key")
	if signKeyB64 != "" {
		keyBytes, err := base64.RawURLEncoding.DecodeString(signKeyB64)
		if err != nil {
			return nil, fmt.Errorf("decode signing key: %w", err)
		}
		key, err := jwk.ParseKey(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("parse signing key: %w", err)
		}
		tm.signingKey = key
	}

	// 加载加密密钥
	encKeyB64 := config.GetString("kms.token.enc-key")
	if encKeyB64 != "" {
		keyBytes, err := base64.RawURLEncoding.DecodeString(encKeyB64)
		if err != nil {
			return nil, fmt.Errorf("decode encrypt key: %w", err)
		}
		key, err := jwk.ParseKey(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("parse encrypt key: %w", err)
		}
		tm.encryptKey = key
	}

	return tm, nil
}

// CreateAccessToken 创建 Access Token
// B 端用户使用，sub 是 JWE 加密的用户 ID
func (tm *TokenManager) CreateAccessToken(userID string, clientID string, domain Domain, ttl time.Duration) (string, error) {
	now := time.Now()

	// 加密 sub（用户 ID）
	encryptedSub, err := tm.encryptSub(userID)
	if err != nil {
		return "", fmt.Errorf("encrypt sub: %w", err)
	}

	// 创建 JWT
	token := jwt.New()
	_ = token.Set(jwt.IssuerKey, tm.issuer)
	_ = token.Set(jwt.SubjectKey, encryptedSub)
	_ = token.Set(jwt.AudienceKey, clientID)
	_ = token.Set(jwt.IssuedAtKey, now.Unix())
	_ = token.Set(jwt.ExpirationKey, now.Add(ttl).Unix())
	_ = token.Set(jwt.NotBeforeKey, now.Unix())

	// JTI
	jtiBytes := make([]byte, 16)
	_, _ = rand.Read(jtiBytes)
	_ = token.Set(jwt.JwtIDKey, hex.EncodeToString(jtiBytes))

	// 自定义 claims
	_ = token.Set("domain", string(domain))

	// 签名
	signedToken, err := jwt.Sign(token, jwt.WithKey(jwa.EdDSA(), tm.signingKey))
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}

	return string(signedToken), nil
}

// CreateIDToken 创建 ID Token
// C 端用户使用，sub 是明文用户 ID
func (tm *TokenManager) CreateIDToken(userID string, clientID string, domain Domain, name, picture string, ttl time.Duration) (string, error) {
	now := time.Now()

	token := jwt.New()
	_ = token.Set(jwt.IssuerKey, tm.issuer)
	_ = token.Set(jwt.SubjectKey, userID)
	_ = token.Set(jwt.AudienceKey, clientID)
	_ = token.Set(jwt.IssuedAtKey, now.Unix())
	_ = token.Set(jwt.ExpirationKey, now.Add(ttl).Unix())

	// JTI
	jtiBytes := make([]byte, 16)
	_, _ = rand.Read(jtiBytes)
	_ = token.Set(jwt.JwtIDKey, hex.EncodeToString(jtiBytes))

	// 用户信息
	_ = token.Set("domain", string(domain))
	if name != "" {
		_ = token.Set("name", name)
	}
	if picture != "" {
		_ = token.Set("picture", picture)
	}

	// 签名
	signedToken, err := jwt.Sign(token, jwt.WithKey(jwa.EdDSA(), tm.signingKey))
	if err != nil {
		return "", fmt.Errorf("sign id token: %w", err)
	}

	return string(signedToken), nil
}

// VerifyAccessToken 验证 Access Token
func (tm *TokenManager) VerifyAccessToken(tokenString string) (*Identity, error) {
	// 验证签名
	token, err := jwt.Parse([]byte(tokenString),
		jwt.WithKey(jwa.EdDSA(), tm.signingKey),
		jwt.WithValidate(true),
	)
	if err != nil {
		return nil, fmt.Errorf("verify token: %w", err)
	}

	// 获取加密的 sub
	encryptedSub, ok := token.Subject()
	if !ok {
		return nil, errors.New("missing sub")
	}

	// 解密 sub
	userID, err := tm.decryptSub(encryptedSub)
	if err != nil {
		return nil, fmt.Errorf("decrypt sub: %w", err)
	}

	// 获取 domain
	var domain string
	_ = token.Get("domain", &domain)

	return &Identity{
		UserID: userID,
		Domain: Domain(domain),
	}, nil
}

// VerifyIDToken 验证 ID Token
func (tm *TokenManager) VerifyIDToken(tokenString string) (*Identity, error) {
	token, err := jwt.Parse([]byte(tokenString),
		jwt.WithKey(jwa.EdDSA(), tm.signingKey),
		jwt.WithValidate(true),
	)
	if err != nil {
		return nil, fmt.Errorf("verify token: %w", err)
	}

	sub, ok := token.Subject()
	if !ok {
		return nil, errors.New("missing sub")
	}

	var domain string
	_ = token.Get("domain", &domain)

	return &Identity{
		UserID: sub,
		Domain: Domain(domain),
	}, nil
}

// encryptSub 加密用户 ID
func (tm *TokenManager) encryptSub(userID string) (string, error) {
	if tm.encryptKey == nil {
		return userID, nil // 没有加密密钥则不加密
	}

	encrypted, err := jwe.Encrypt([]byte(userID),
		jwe.WithKey(jwa.DIRECT(), tm.encryptKey),
		jwe.WithContentEncryption(jwa.A256GCM()),
	)
	if err != nil {
		return "", err
	}

	return string(encrypted), nil
}

// decryptSub 解密用户 ID
func (tm *TokenManager) decryptSub(encryptedSub string) (string, error) {
	if tm.encryptKey == nil {
		return encryptedSub, nil
	}

	decrypted, err := jwe.Decrypt([]byte(encryptedSub),
		jwe.WithKey(jwa.DIRECT(), tm.encryptKey),
	)
	if err != nil {
		return "", err
	}

	return string(decrypted), nil
}

// GenerateAuthorizationCode 生成授权码
func GenerateAuthorizationCode() string {
	bytes := make([]byte, 32)
	_, _ = rand.Read(bytes)
	return base64.RawURLEncoding.EncodeToString(bytes)
}

// GenerateSessionID 生成会话 ID
func GenerateSessionID() string {
	bytes := make([]byte, 16)
	_, _ = rand.Read(bytes)
	return base64.RawURLEncoding.EncodeToString(bytes)
}

// VerifyCodeChallenge 验证 PKCE
func VerifyCodeChallenge(method CodeChallengeMethod, challenge, verifier string) bool {
	switch method {
	case CodeChallengeMethodS256:
		hash := sha256.Sum256([]byte(verifier))
		computed := base64.RawURLEncoding.EncodeToString(hash[:])
		return computed == challenge
	case CodeChallengeMethodPlain:
		return challenge == verifier
	default:
		return false
	}
}

// VerifyAccessToken 兼容旧接口（全局函数）
func VerifyAccessToken(tokenString string) (*Identity, error) {
	tm, err := NewTokenManager()
	if err != nil {
		return nil, err
	}
	// 先尝试 Access Token，再尝试 ID Token
	identity, err := tm.VerifyAccessToken(tokenString)
	if err != nil {
		identity, err = tm.VerifyIDToken(tokenString)
	}
	return identity, err
}
