package token

import (
	"fmt"
	"strings"
	"time"

	"aidanwoods.dev/go-paseto"

	"github.com/heliannuuthus/helios/pkg/aegis/token"
)

// UserAccessToken 用户访问令牌
// 包含用户身份信息，用户信息加密后存储在 footer 中
type UserAccessToken struct {
	token.Claims                 // 内嵌基础 Claims
	scope        string          // 授权范围
	user         *token.UserInfo // 用户信息（构建时设置/解密后填充）
}

// NewUserAccessToken 创建 UserAccessToken（用于签发）
func NewUserAccessToken(issuer, clientID, audience, scope string, expiresIn time.Duration, user *token.UserInfo) *UserAccessToken {
	return &UserAccessToken{
		Claims: token.NewClaims(issuer, clientID, audience, expiresIn),
		scope:  scope,
		user:   user,
	}
}

// parseUserAccessToken 从 PASETO Token 解析 UserAccessToken（用于验证后）
func parseUserAccessToken(pasetoToken *paseto.Token) (*UserAccessToken, error) {
	claims, err := token.ParseClaims(pasetoToken)
	if err != nil {
		return nil, fmt.Errorf("parse claims: %w", err)
	}

	var scope string
	if err := pasetoToken.Get("scope", &scope); err != nil {
		// scope 是可选字段
		scope = ""
	}

	return &UserAccessToken{
		Claims: claims,
		scope:  scope,
	}, nil
}

// Build 构建 PASETO Token（不包含签名）
// 注意：用户信息需要加密后放入 footer，由 Service 处理
func (u *UserAccessToken) Build() (*paseto.Token, error) {
	t := paseto.NewToken()
	if err := u.SetStandardClaims(&t); err != nil {
		return nil, fmt.Errorf("set standard claims: %w", err)
	}
	if err := t.Set("scope", u.scope); err != nil {
		return nil, fmt.Errorf("set scope: %w", err)
	}
	return &t, nil
}

// ExpiresIn 实现 AccessToken 接口
func (u *UserAccessToken) ExpiresIn() time.Duration {
	return u.GetExpiresIn()
}

// GetScope 返回授权范围
func (u *UserAccessToken) GetScope() string {
	return u.scope
}

// HasScope 检查是否包含某个 scope
func (u *UserAccessToken) HasScope(scope string) bool {
	return token.HasScope(u.scope, scope)
}

// GetUser 返回用户信息
func (u *UserAccessToken) GetUser() *token.UserInfo {
	return u.user
}

// SetUser 设置用户信息（解密后调用）
func (u *UserAccessToken) SetUser(user *token.UserInfo) {
	u.user = user
}

// UserInfoFromScope 根据 scope 构建用户信息
// scope 决定哪些用户信息会被包含在 token 中
func UserInfoFromScope(openID, nickname, picture, email, phone, scope string) *token.UserInfo {
	info := &token.UserInfo{
		Subject: openID,
	}

	// 根据 scope 填充字段
	scopeSet := parseScopeSet(scope)

	if scopeSet["profile"] {
		info.Nickname = nickname
		info.Picture = picture
	}

	if scopeSet["email"] {
		info.Email = email
	}

	if scopeSet["phone"] {
		info.Phone = phone
	}

	return info
}

// parseScopeSet 解析 scope 字符串为集合
func parseScopeSet(scope string) map[string]bool {
	set := make(map[string]bool)
	for _, s := range strings.Fields(scope) {
		set[s] = true
	}
	return set
}
