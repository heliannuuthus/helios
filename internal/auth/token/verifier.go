package token

import (
	"context"
	"errors"
	"fmt"

	"github.com/heliannuuthus/helios/internal/auth/cache"
	"github.com/heliannuuthus/helios/pkg/json"
	pkgtoken "github.com/heliannuuthus/helios/pkg/token"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// Verifier Token 验证器
// 用于 auth 服务内部验证自己签发的 UAT/SAT
type Verifier struct {
	cache *cache.HermesCache
}

// NewVerifier 创建 Token 验证器
func NewVerifier(hermesCache *cache.HermesCache) *Verifier {
	return &Verifier{
		cache: hermesCache,
	}
}

// VerifyAccessToken 验证 Access Token (UAT/SAT)
// 自动从 token 中解析 audience 和 clientID，获取对应的密钥进行验证
func (v *Verifier) VerifyAccessToken(ctx context.Context, tokenString string) (*Identity, error) {
	// 1. 先解析 token（不验证）获取 aud 和 cli
	unverified, err := jwt.Parse([]byte(tokenString), jwt.WithVerify(false))
	if err != nil {
		return nil, fmt.Errorf("parse token: %w", err)
	}

	audVal, ok := unverified.Audience()
	if !ok || len(audVal) == 0 {
		return nil, errors.New("missing aud")
	}
	audience := audVal[0]

	var clientID string
	if err := unverified.Get("cli", &clientID); err != nil || clientID == "" {
		return nil, errors.New("missing cli")
	}

	// 2. 获取服务加密密钥（用于解密 sub）
	svc, err := v.cache.GetService(ctx, audience)
	if err != nil {
		return nil, fmt.Errorf("get service key: %w", err)
	}

	// 3. 通过 clientID 获取应用信息，进而获取 domain
	app, err := v.cache.GetApplication(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("get application: %w", err)
	}

	// 4. 获取域签名密钥（用于验签）
	domain, err := v.cache.GetDomain(ctx, app.DomainID)
	if err != nil {
		return nil, fmt.Errorf("get domain key: %w", err)
	}

	// 5. 解析签名密钥
	signKey, err := jwk.ParseKey(domain.SignKey)
	if err != nil {
		return nil, fmt.Errorf("parse sign key: %w", err)
	}

	// 6. 验证签名
	token, err := jwt.Parse([]byte(tokenString),
		jwt.WithKey(jwa.EdDSA(), signKey),
		jwt.WithValidate(true),
	)
	if err != nil {
		return nil, fmt.Errorf("verify token: %w", err)
	}

	// 7. 获取加密的 sub（可能不存在，如 SAT）
	encryptedSub, hasSub := token.Subject()

	var claims *pkgtoken.Claims
	if hasSub && encryptedSub != "" {
		// 8. 解密 sub（UAT）
		claims, err = v.decryptClaims(encryptedSub, svc.Key)
		if err != nil {
			return nil, fmt.Errorf("decrypt sub: %w", err)
		}
	}

	// 获取 scope
	var scope string
	_ = token.Get("scope", &scope)

	identity := &Identity{
		ClientID: clientID,
		Audience: audience,
		Scope:    scope,
	}

	// 填充用户信息（如果有）
	if claims != nil {
		identity.OpenID = claims.OpenID
		identity.Nickname = claims.Nickname
		identity.Picture = claims.Picture
		identity.Email = claims.Email
		identity.Phone = claims.Phone
	}

	return identity, nil
}

// decryptClaims 解密用户信息
func (v *Verifier) decryptClaims(encryptedSub string, decryptKey []byte) (*pkgtoken.Claims, error) {
	key, err := jwk.Import(decryptKey)
	if err != nil {
		return nil, fmt.Errorf("import decrypt key: %w", err)
	}

	decrypted, err := jwe.Decrypt([]byte(encryptedSub),
		jwe.WithKey(jwa.DIRECT(), key),
	)
	if err != nil {
		return nil, err
	}

	var claims pkgtoken.Claims
	if err := json.Unmarshal(decrypted, &claims); err != nil {
		return nil, err
	}

	return &claims, nil
}

// ParseAccessTokenUnverified 解析 Token 但不验证（用于获取 claims）
func (v *Verifier) ParseAccessTokenUnverified(tokenString string) (aud string, iss string, exp int64, iat int64, scope string, err error) {
	token, parseErr := jwt.Parse([]byte(tokenString), jwt.WithVerify(false))
	if parseErr != nil {
		err = parseErr
		return
	}

	if audVal, ok := token.Audience(); ok && len(audVal) > 0 {
		aud = audVal[0]
	}
	if issVal, ok := token.Issuer(); ok {
		iss = issVal
	}
	if expVal, ok := token.Expiration(); ok {
		exp = expVal.Unix()
	}
	if iatVal, ok := token.IssuedAt(); ok {
		iat = iatVal.Unix()
	}
	_ = token.Get("scope", &scope)
	return
}

// VerifyServiceJWT 验证 Service JWT（用于 introspect）
func (v *Verifier) VerifyServiceJWT(tokenString string, serviceKey []byte) (serviceID string, jti string, err error) {
	key, err := jwk.Import(serviceKey)
	if err != nil {
		return "", "", fmt.Errorf("import service key: %w", err)
	}

	token, err := jwt.Parse([]byte(tokenString),
		jwt.WithKey(jwa.HS256(), key),
		jwt.WithValidate(true),
	)
	if err != nil {
		return "", "", fmt.Errorf("verify service jwt: %w", err)
	}

	sub, ok := token.Subject()
	if !ok {
		return "", "", errors.New("missing sub in service jwt")
	}

	jtiVal, _ := token.JwtID()

	return sub, jtiVal, nil
}
