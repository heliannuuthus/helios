package token

import (
	"time"

	"github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/heliannuuthus/helios/pkg/utils"
)

// ServiceAccessToken 服务访问令牌
// 用于 M2M（机器对机器）通信，不包含用户信息
type ServiceAccessToken struct {
	issuer    string        // 签发者
	clientID  string        // cli - 应用 ID
	audience  string        // aud - 服务 ID
	scope     string        // 授权范围
	ttl       time.Duration // 有效期
	notBefore time.Time     // 生效时间
}

// NewServiceAccessToken 创建 ServiceAccessToken
func NewServiceAccessToken(issuer, clientID, audience, scope string, ttl time.Duration) *ServiceAccessToken {
	return &ServiceAccessToken{
		issuer:    issuer,
		clientID:  clientID,
		audience:  audience,
		scope:     scope,
		ttl:       ttl,
		notBefore: time.Now(),
	}
}

// Build 构建 JWT Token（不包含签名）
// ServiceAccessToken 没有 sub 字段（无用户信息）
func (s *ServiceAccessToken) Build() (jwt.Token, error) {
	now := time.Now()

	return jwt.NewBuilder().
		Issuer(s.issuer).
		Audience([]string{s.audience}). // aud = service_id
		Claim("cli", s.clientID).       // cli = client_id
		IssuedAt(now).
		Expiration(now.Add(s.ttl)).
		NotBefore(s.notBefore).
		JwtID(utils.GenerateJTI()).
		Claim("scope", s.scope).
		Build()
}

// GetIssuer 返回签发者
func (s *ServiceAccessToken) GetIssuer() string {
	return s.issuer
}

// GetClientID 返回应用 ID
func (s *ServiceAccessToken) GetClientID() string {
	return s.clientID
}

// GetAudience 返回服务 ID
func (s *ServiceAccessToken) GetAudience() string {
	return s.audience
}

// ExpiresIn 返回有效期
func (s *ServiceAccessToken) ExpiresIn() time.Duration {
	return s.ttl
}

// GetNotBefore 返回生效时间
func (s *ServiceAccessToken) GetNotBefore() time.Time {
	return s.notBefore
}

// GetScope 返回授权范围
func (s *ServiceAccessToken) GetScope() string {
	return s.scope
}
