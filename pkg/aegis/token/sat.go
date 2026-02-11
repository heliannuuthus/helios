package token

import (
	"fmt"
	"time"

	"aidanwoods.dev/go-paseto"
)

// ServiceAccessToken 服务访问令牌
// 用于 M2M（机器对机器）通信，不包含用户信息
type ServiceAccessToken struct {
	Claims        // 内嵌基础 Claims
	scope  string // 授权范围
}

// ==================== SAT TokenTypeBuilder ====================

// SAT SAT 类型构建器，实现 TokenTypeBuilder 接口
type SAT struct {
	scope string
}

// NewServiceAccessTokenBuilder 创建 SAT 类型构建器
func NewServiceAccessTokenBuilder() *SAT {
	return &SAT{}
}

// Scope 设置授权范围
func (s *SAT) Scope(scope string) *SAT {
	s.scope = scope
	return s
}

// build 实现 TokenTypeBuilder 接口
func (s *SAT) build(claims Claims) Token {
	return &ServiceAccessToken{
		Claims: claims,
		scope:  s.scope,
	}
}

// ==================== 解析函数 ====================

// ParseServiceAccessToken 从 PASETO Token 解析 ServiceAccessToken（用于验证后）
func ParseServiceAccessToken(pasetoToken *paseto.Token) (*ServiceAccessToken, error) {
	claims, err := ParseClaims(pasetoToken)
	if err != nil {
		return nil, fmt.Errorf("parse claims: %w", err)
	}

	var scope string
	if err := pasetoToken.Get(ClaimScope, &scope); err != nil {
		// scope 是可选字段
		scope = ""
	}

	return &ServiceAccessToken{
		Claims: claims,
		scope:  scope,
	}, nil
}

// ==================== Token 接口实现 ====================

// Type 实现 Token 接口
func (s *ServiceAccessToken) Type() TokenType {
	return TokenTypeSAT
}

// build 实现 tokenBuilder 接口（小写，内部使用）
func (s *ServiceAccessToken) build() (*paseto.Token, error) {
	return s.BuildPaseto()
}

// BuildPaseto 构建 PASETO Token（不包含签名）
// ServiceAccessToken 没有 footer（无用户信息）
func (s *ServiceAccessToken) BuildPaseto() (*paseto.Token, error) {
	t := paseto.NewToken()
	if err := s.SetStandardClaims(&t); err != nil {
		return nil, fmt.Errorf("set standard claims: %w", err)
	}
	if err := t.Set(ClaimScope, s.scope); err != nil {
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

// HasScope 检查是否包含某个 scope
func (s *ServiceAccessToken) HasScope(scope string) bool {
	return HasScope(s.scope, scope)
}
