package token

import (
	"fmt"
	"time"

	"aidanwoods.dev/go-paseto"
)

// ClientAccessToken 用于 Client-Credentials 流程
// 应用使用自己的 Ed25519 密钥签发 PASETO v4 Public Token，向 Auth Service 请求 ServiceAccessToken
//
// 注意：CAT 的 sub 字段是 clientID（与其他 Token 不同，其他 Token 使用 cli 字段）
type ClientAccessToken struct {
	Claims // 内嵌基础 Claims
}

// ==================== CAT TokenTypeBuilder ====================

// CAT CAT 类型构建器，实现 TokenTypeBuilder 接口
// CAT 没有额外字段，只需要基础 Claims
type CAT struct{}

// NewClientAccessTokenBuilder 创建 CAT 类型构建器
func NewClientAccessTokenBuilder() *CAT {
	return &CAT{}
}

// build 实现 TokenTypeBuilder 接口
func (c *CAT) Build(claims Claims) Token {
	return &ClientAccessToken{
		Claims: claims,
	}
}

// ==================== 解析函数 ====================

// ParseClientAccessToken 从 PASETO Token 解析 ClientAccessToken（用于验证后）
// 注意：CAT 的 clientID 从 sub 字段获取，而不是 cli 字段
func ParseClientAccessToken(pasetoToken *paseto.Token) (*ClientAccessToken, error) {
	issuer, err := pasetoToken.GetIssuer()
	if err != nil {
		return nil, fmt.Errorf("get issuer: %w", err)
	}

	clientID, err := pasetoToken.GetSubject() // CAT 使用 sub = clientID
	if err != nil {
		return nil, fmt.Errorf("get subject: %w", err)
	}

	audience, err := pasetoToken.GetAudience()
	if err != nil {
		return nil, fmt.Errorf("get audience: %w", err)
	}

	issuedAt, err := pasetoToken.GetIssuedAt()
	if err != nil {
		return nil, fmt.Errorf("get issued_at: %w", err)
	}

	expiresAt, err := pasetoToken.GetExpiration()
	if err != nil {
		return nil, fmt.Errorf("get expiration: %w", err)
	}

	jti, err := pasetoToken.GetJti()
	if err != nil {
		return nil, fmt.Errorf("get jti: %w", err)
	}

	return &ClientAccessToken{
		Claims: Claims{
			Issuer:    issuer,
			ClientID:  clientID,
			Audience:  audience,
			IssuedAt:  issuedAt,
			ExpiresAt: expiresAt,
			JTI:       jti,
		},
	}, nil
}

// ==================== Token 接口实现 ====================

// Type 实现 Token 接口
func (c *ClientAccessToken) Type() TokenType {
	return TokenTypeCAT
}

// Build 构建 PASETO Token（不包含签名）
func (c *ClientAccessToken) Build() (*paseto.Token, error) {
	now := time.Now()
	t := paseto.NewToken()

	t.SetIssuer(c.Issuer)
	t.SetSubject(c.ClientID) // sub = client_id（CAT 特殊）
	t.SetAudience(c.Audience)
	t.SetIssuedAt(now)
	t.SetExpiration(now.Add(c.Claims.ExpiresIn))
	t.SetNotBefore(now)
	t.SetJti(c.JTI)

	return &t, nil
}

// ExpiresIn 实现 AccessToken 接口
func (c *ClientAccessToken) ExpiresIn() time.Duration {
	return c.GetExpiresIn()
}
