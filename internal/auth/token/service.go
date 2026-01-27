package token

import (
	"context"
	"errors"
	"fmt"

	"github.com/heliannuuthus/helios/internal/auth/cache"
	"github.com/heliannuuthus/helios/internal/config"
	"github.com/heliannuuthus/helios/pkg/json"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// Service Token 服务
// 负责签发 UAT/SAT、验证 CAT/ServiceJWT、解析 token
type Service struct {
	issuerName string
	cache      *cache.HermesCache
}

// NewService 创建 Token 服务
func NewService(hermesCache *cache.HermesCache) *Service {
	return &Service{
		issuerName: config.GetIssuer(),
		cache:      hermesCache,
	}
}

// GetIssuerName 返回签发者名称
func (s *Service) GetIssuerName() string {
	return s.issuerName
}

// ============= 签发 =============

// Issue 签发 token
func (s *Service) Issue(ctx context.Context, accessToken AccessToken) (string, error) {
	switch t := accessToken.(type) {
	case *UserAccessToken:
		return s.issueUserToken(ctx, t)
	case *ServiceAccessToken:
		return s.issueServiceToken(ctx, t)
	default:
		return "", errors.New("unsupported token type")
	}
}

// issueUserToken 签发用户访问令牌
func (s *Service) issueUserToken(ctx context.Context, uat *UserAccessToken) (string, error) {
	// 1. 加密 user claims 到 sub
	if uat.GetUser() == nil {
		return "", errors.New("user claims required for UserAccessToken")
	}
	encryptedSub, err := s.encrypt(ctx, uat)
	if err != nil {
		return "", fmt.Errorf("encrypt user claims: %w", err)
	}

	// 2. 构建 JWT 并设置加密后的 sub
	token, err := uat.Build()
	if err != nil {
		return "", fmt.Errorf("build token: %w", err)
	}
	_ = token.Set(jwt.SubjectKey, encryptedSub)

	// 3. 签名
	signed, err := s.sign(ctx, token, uat.GetClientID())
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}

	return string(signed), nil
}

// issueServiceToken 签发服务访问令牌
func (s *Service) issueServiceToken(ctx context.Context, sat *ServiceAccessToken) (string, error) {
	// 1. 构建 JWT
	token, err := sat.Build()
	if err != nil {
		return "", fmt.Errorf("build token: %w", err)
	}

	// 2. 签名
	signed, err := s.sign(ctx, token, sat.GetClientID())
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}

	return string(signed), nil
}

// ============= 验证 =============

// CATClaims 验证 CAT/ServiceJWT 后返回的信息
type CATClaims struct {
	ClientID string // 应用或服务 ID（sub）
	Audience string // 目标服务（aud）
	JTI      string // JWT ID
}

// VerifyCAT 验证 ClientAccessToken
// CAT 由应用使用其密钥签发，用于 Client-Credentials 流程
func (s *Service) VerifyCAT(ctx context.Context, tokenString string) (*CATClaims, error) {
	// 1. 解析 token 获取 sub
	unverified, err := jwt.Parse([]byte(tokenString), jwt.WithVerify(false))
	if err != nil {
		return nil, fmt.Errorf("parse token: %w", err)
	}

	clientID, ok := unverified.Subject()
	if !ok || clientID == "" {
		return nil, errors.New("missing sub (client_id)")
	}

	// 2. 获取应用密钥
	app, err := s.cache.GetApplication(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("get application: %w", err)
	}

	if len(app.Key) == 0 {
		return nil, errors.New("application has no key")
	}

	// 3. 验证签名
	key, err := jwk.Import(app.Key)
	if err != nil {
		return nil, fmt.Errorf("import app key: %w", err)
	}

	token, err := jwt.Parse([]byte(tokenString),
		jwt.WithKey(jwa.HS256(), key),
		jwt.WithValidate(true),
	)
	if err != nil {
		return nil, fmt.Errorf("verify token: %w", err)
	}

	return s.extractCATClaims(token, clientID), nil
}

// VerifyServiceJWT 验证 Service JWT（用于 introspect）
func (s *Service) VerifyServiceJWT(ctx context.Context, tokenString string) (*CATClaims, error) {
	// 1. 解析 token 获取 sub
	unverified, err := jwt.Parse([]byte(tokenString), jwt.WithVerify(false))
	if err != nil {
		return nil, fmt.Errorf("parse token: %w", err)
	}

	serviceID, ok := unverified.Subject()
	if !ok || serviceID == "" {
		return nil, errors.New("missing sub (service_id)")
	}

	// 2. 获取服务密钥
	svc, err := s.cache.GetService(ctx, serviceID)
	if err != nil {
		return nil, fmt.Errorf("get service: %w", err)
	}

	// 3. 验证签名
	key, err := jwk.Import(svc.Key)
	if err != nil {
		return nil, fmt.Errorf("import service key: %w", err)
	}

	token, err := jwt.Parse([]byte(tokenString),
		jwt.WithKey(jwa.HS256(), key),
		jwt.WithValidate(true),
	)
	if err != nil {
		return nil, fmt.Errorf("verify token: %w", err)
	}

	return s.extractCATClaims(token, serviceID), nil
}

// ============= 解析 =============

// TokenInfo 解析 Token 后的信息（不含验证）
type TokenInfo struct {
	Issuer   string
	Audience string
	ClientID string
	Scope    string
	Sub      string // 可能是加密的用户信息
	Exp      int64
	Iat      int64
}

// Parse 解析 Access Token（不验证）
func (s *Service) Parse(tokenString string) (*TokenInfo, error) {
	token, err := jwt.Parse([]byte(tokenString), jwt.WithVerify(false))
	if err != nil {
		return nil, fmt.Errorf("parse token: %w", err)
	}

	info := &TokenInfo{}

	if audVal, ok := token.Audience(); ok && len(audVal) > 0 {
		info.Audience = audVal[0]
	}
	if issVal, ok := token.Issuer(); ok {
		info.Issuer = issVal
	}
	if expVal, ok := token.Expiration(); ok {
		info.Exp = expVal.Unix()
	}
	if iatVal, ok := token.IssuedAt(); ok {
		info.Iat = iatVal.Unix()
	}
	_ = token.Get("scope", &info.Scope)
	_ = token.Get("cli", &info.ClientID)

	if sub, ok := token.Subject(); ok {
		info.Sub = sub
	}

	return info, nil
}

// ============= 内部方法 =============

// sign 签名 JWT
func (s *Service) sign(ctx context.Context, token jwt.Token, clientID string) ([]byte, error) {
	// 1. 获取应用信息
	app, err := s.cache.GetApplication(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("get application: %w", err)
	}

	// 2. 获取域签名密钥
	domain, err := s.cache.GetDomain(ctx, app.DomainID)
	if err != nil {
		return nil, fmt.Errorf("get domain: %w", err)
	}

	// 3. 解析签名密钥
	signKey, err := jwk.ParseKey(domain.SignKey)
	if err != nil {
		return nil, fmt.Errorf("parse sign key: %w", err)
	}

	// 4. 签名
	return jwt.Sign(token, jwt.WithKey(jwa.EdDSA(), signKey))
}

// encrypt 加密用户信息
func (s *Service) encrypt(ctx context.Context, uat *UserAccessToken) (string, error) {
	// 1. 获取服务加密密钥
	svc, err := s.cache.GetService(ctx, uat.GetAudience())
	if err != nil {
		return "", fmt.Errorf("get service key: %w", err)
	}

	// 2. 序列化 claims
	data, err := json.Marshal(uat.GetUser())
	if err != nil {
		return "", fmt.Errorf("marshal claims: %w", err)
	}

	// 3. 导入密钥
	key, err := jwk.Import(svc.Key)
	if err != nil {
		return "", fmt.Errorf("import encrypt key: %w", err)
	}

	// 4. 加密
	encrypted, err := jwe.Encrypt(data,
		jwe.WithKey(jwa.DIRECT(), key),
		jwe.WithContentEncryption(jwa.A256GCM()),
	)
	if err != nil {
		return "", fmt.Errorf("jwe encrypt: %w", err)
	}

	return string(encrypted), nil
}

// extractCATClaims 提取 CAT claims
func (s *Service) extractCATClaims(token jwt.Token, id string) *CATClaims {
	audVal, ok := token.Audience()
	var audience string
	if ok && len(audVal) > 0 {
		audience = audVal[0]
	}

	jti, _ := token.JwtID()

	return &CATClaims{
		ClientID: id,
		Audience: audience,
		JTI:      jti,
	}
}

// ============= 兼容旧接口 =============

// Issuer 类型别名，兼容旧代码
// Deprecated: 使用 Service 替代
type Issuer = Service

// NewIssuer 兼容旧代码
// Deprecated: 使用 NewService 替代
func NewIssuer(hermesCache *cache.HermesCache) *Issuer {
	return NewService(hermesCache)
}

// ClientAccessTokenClaims 类型别名
// Deprecated: 使用 CATClaims 替代
type ClientAccessTokenClaims = CATClaims

// VerifyClientAccessToken 兼容旧代码
// Deprecated: 使用 VerifyCAT 替代
func (s *Service) VerifyClientAccessToken(ctx context.Context, tokenString string) (*CATClaims, error) {
	return s.VerifyCAT(ctx, tokenString)
}

// AccessTokenInfo 类型别名
// Deprecated: 使用 TokenInfo 替代
type AccessTokenInfo = TokenInfo

// ParseAccessTokenUnverified 兼容旧代码
// Deprecated: 使用 Parse 替代
func (s *Service) ParseAccessTokenUnverified(tokenString string) (*TokenInfo, error) {
	return s.Parse(tokenString)
}
