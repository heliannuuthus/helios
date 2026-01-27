package token

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/heliannuuthus/helios/internal/auth/cache"
	pkgtoken "github.com/heliannuuthus/helios/pkg/token"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// Issuer Token 签发器
type Issuer struct {
	issuerName string
	cache      *cache.HermesCache
}

// NewIssuer 创建 Token 签发器
func NewIssuer(issuerName string, hermesCache *cache.HermesCache) *Issuer {
	return &Issuer{
		issuerName: issuerName,
		cache:      hermesCache,
	}
}

// GetIssuerName 返回签发者名称
func (i *Issuer) GetIssuerName() string {
	return i.issuerName
}

// IssueUserToken 签发用户访问令牌
// clientID: 应用 ID
// audience: 服务 ID（用于获取加密密钥）
// domain: 域 ID（用于获取签名密钥）
func (i *Issuer) IssueUserToken(
	ctx context.Context,
	clientID, audience, domain, scope string,
	ttl time.Duration,
	user *pkgtoken.Claims,
) (string, error) {
	// 获取服务加密密钥
	svcWithKey, err := i.cache.GetServiceWithKey(ctx, audience)
	if err != nil {
		return "", fmt.Errorf("get service key: %w", err)
	}

	// 获取域签名密钥
	domainWithKey, err := i.cache.GetDomain(ctx, domain)
	if err != nil {
		return "", fmt.Errorf("get domain key: %w", err)
	}

	// 构建 token
	uat := NewUserAccessToken(i.issuerName, clientID, audience, scope, ttl, user)
	return i.issue(uat, svcWithKey.Key, domainWithKey.SignKey)
}

// IssueServiceToken 签发服务访问令牌（M2M，无用户信息）
func (i *Issuer) IssueServiceToken(
	ctx context.Context,
	clientID, audience, domain, scope string,
	ttl time.Duration,
) (string, error) {
	// 获取域签名密钥
	domainWithKey, err := i.cache.GetDomain(ctx, domain)
	if err != nil {
		return "", fmt.Errorf("get domain key: %w", err)
	}

	// 构建 token（ServiceAccessToken 不需要加密密钥）
	sat := NewServiceAccessToken(i.issuerName, clientID, audience, scope, ttl)
	return i.issue(sat, nil, domainWithKey.SignKey)
}

// issue 内部签发方法
func (i *Issuer) issue(accessToken AccessToken, encryptKey, signKey []byte) (string, error) {
	// 解析签名密钥
	signer, err := jwk.ParseKey(signKey)
	if err != nil {
		return "", fmt.Errorf("parse sign key: %w", err)
	}

	// 构建 JWT Token
	token, err := accessToken.Build()
	if err != nil {
		return "", fmt.Errorf("build token: %w", err)
	}

	// 如果是 UserAccessToken，需要加密用户信息到 sub
	if uat, ok := accessToken.(*UserAccessToken); ok && uat.GetUser() != nil {
		if encryptKey == nil {
			return "", errors.New("encrypt key required for UserAccessToken")
		}
		encryptedSub, err := i.encryptClaims(uat.GetUser(), encryptKey)
		if err != nil {
			return "", fmt.Errorf("encrypt user claims: %w", err)
		}
		_ = token.Set(jwt.SubjectKey, encryptedSub)
	}

	// 签名
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.EdDSA(), signer))
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}

	return string(signed), nil
}

// encryptClaims 加密用户信息
func (i *Issuer) encryptClaims(claims *pkgtoken.Claims, encryptKey []byte) (string, error) {
	data, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal claims: %w", err)
	}

	key, err := jwk.Import(encryptKey)
	if err != nil {
		return "", fmt.Errorf("import encrypt key: %w", err)
	}

	encrypted, err := jwe.Encrypt(data,
		jwe.WithKey(jwa.DIRECT(), key),
		jwe.WithContentEncryption(jwa.A256GCM()),
	)
	if err != nil {
		return "", fmt.Errorf("jwe encrypt: %w", err)
	}

	return string(encrypted), nil
}

// decryptClaims 解密用户信息
func (i *Issuer) decryptClaims(encryptedSub string, decryptKey []byte) (*pkgtoken.Claims, error) {
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

// VerifyAccessToken 验证 Access Token
// 自动从 token 中解析 audience 和 clientID，获取对应的密钥进行验证
func (i *Issuer) VerifyAccessToken(ctx context.Context, tokenString string) (*Identity, error) {
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
	svcWithKey, err := i.cache.GetServiceWithKey(ctx, audience)
	if err != nil {
		return nil, fmt.Errorf("get service key: %w", err)
	}

	// 3. 通过 clientID 获取应用信息，进而获取 domain
	app, err := i.cache.GetApplication(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("get application: %w", err)
	}

	// 4. 获取域签名密钥（用于验签）
	domainWithKey, err := i.cache.GetDomain(ctx, app.DomainID)
	if err != nil {
		return nil, fmt.Errorf("get domain key: %w", err)
	}

	// 5. 解析签名密钥
	signKey, err := jwk.ParseKey(domainWithKey.SignKey)
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

	// 7. 获取加密的 sub
	encryptedSub, ok := token.Subject()
	if !ok {
		return nil, errors.New("missing sub")
	}

	// 8. 解密 sub
	claims, err := i.decryptClaims(encryptedSub, svcWithKey.Key)
	if err != nil {
		return nil, fmt.Errorf("decrypt sub: %w", err)
	}

	// 获取 scope
	var scope string
	_ = token.Get("scope", &scope)

	return &Identity{
		OpenID:   claims.OpenID,
		ClientID: clientID,
		Audience: audience,
		Scope:    scope,
		Nickname: claims.Nickname,
		Picture:  claims.Picture,
		Email:    claims.Email,
		Phone:    claims.Phone,
	}, nil
}

// ParseAccessTokenUnverified 解析 Token 但不验证（用于获取 claims）
func (i *Issuer) ParseAccessTokenUnverified(tokenString string) (aud string, iss string, exp int64, iat int64, scope string, err error) {
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
func (i *Issuer) VerifyServiceJWT(tokenString string, serviceKey []byte) (serviceID string, jti string, err error) {
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

// VerifyAccessTokenGlobal 兼容旧接口（全局函数）
// Deprecated: 使用 Issuer.VerifyAccessToken 替代
func VerifyAccessTokenGlobal(tokenString string) (*Identity, error) {
	return nil, errors.New("VerifyAccessTokenGlobal is deprecated, use Issuer.VerifyAccessToken instead")
}
