package token

import (
	"fmt"
	"time"

	"aidanwoods.dev/go-paseto"

	"github.com/heliannuuthus/helios/pkg/aegis/token"
)

// ServiceAccessToken 服务访问令牌
// 用于 M2M（机器对机器）通信，不包含用户信息
type ServiceAccessToken struct {
	token.Claims        // 内嵌基础 Claims
	scope        string // 授权范围
}

// NewServiceAccessToken 创建 ServiceAccessToken（用于签发）
func NewServiceAccessToken(issuer, clientID, audience, scope string, expiresIn time.Duration) *ServiceAccessToken {
	return &ServiceAccessToken{
		Claims: token.NewClaims(issuer, clientID, audience, expiresIn),
		scope:  scope,
	}
}

// ParseServiceAccessToken 从 PASETO Token 解析 ServiceAccessToken（用于验证后）
func ParseServiceAccessToken(pasetoToken *paseto.Token) (*ServiceAccessToken, error) {
	claims, err := token.ParseClaims(pasetoToken)
	if err != nil {
		return nil, fmt.Errorf("parse claims: %w", err)
	}

	var scope string
	if err := pasetoToken.Get("scope", &scope); err != nil {
		// scope 是可选字段
		scope = ""
	}

	return &ServiceAccessToken{
		Claims: claims,
		scope:  scope,
	}, nil
}

// Build 构建 PASETO Token（不包含签名）
// ServiceAccessToken 没有 footer（无用户信息）
func (s *ServiceAccessToken) Build() (*paseto.Token, error) {
	t := paseto.NewToken()
	if err := s.SetStandardClaims(&t); err != nil {
		return nil, fmt.Errorf("set standard claims: %w", err)
	}
	if err := t.Set("scope", s.scope); err != nil {
		return nil, fmt.Errorf("set scope: %w", err)
	}
	return &t, nil
}

// ExpiresIn 实现 AccessToken 接口
func (s *ServiceAccessToken) ExpiresIn() time.Duration {
	return s.GetExpiresIn()
}

// GetScope 返回授权范围
func (s *ServiceAccessToken) GetScope() string {
	return s.scope
}
