package token

import (
	"fmt"
	"time"

	"aidanwoods.dev/go-paseto"
)

// ClientToken 用于 Client-Credentials 流程
// 应用使用自己的 Ed25519 密钥签发 PASETO v4 Public Token，向 Auth Service 请求 ServiceAccessToken
//
// 注意：CT 的 sub 字段是 clientID（与其他 Token 不同，其他 Token 使用 cli 字段）
type ClientToken struct {
	Claims
}

// ==================== CT TokenTypeBuilder ====================

// CT ClientToken 类型构建器，实现 TokenTypeBuilder 接口
type CT struct{}

// NewClientTokenBuilder 创建 CT 类型构建器
func NewClientTokenBuilder() *CT {
	return &CT{}
}

func (c *CT) Build(claims Claims) Token {
	return &ClientToken{
		Claims: claims,
	}
}

// ==================== 解析函数 ====================

// ParseClientToken 从 PASETO Token 解析 ClientToken（用于验证后）
// 注意：CT 的 clientID 从 sub 字段获取，而不是 cli 字段
func ParseClientToken(pasetoToken *paseto.Token) (*ClientToken, error) {
	issuer, err := pasetoToken.GetIssuer()
	if err != nil {
		return nil, fmt.Errorf("get issuer: %w", err)
	}

	clientID, err := pasetoToken.GetSubject()
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

	return &ClientToken{
		Claims: Claims{
			issuer:    issuer,
			clientID:  clientID,
			audience:  audience,
			issuedAt:  issuedAt,
			expiresAt: expiresAt,
			jti:       jti,
		},
	}, nil
}

// ==================== Token 接口实现 ====================

func (c *ClientToken) Type() TokenType {
	return TokenTypeCT
}

func (c *ClientToken) Build() (*paseto.Token, error) {
	now := time.Now()
	t := paseto.NewToken()

	t.SetIssuer(c.issuer)
	t.SetSubject(c.clientID)
	t.SetAudience(c.audience)
	t.SetIssuedAt(now)
	t.SetExpiration(now.Add(c.expiresIn))
	t.SetNotBefore(now)
	t.SetJti(c.jti)

	return &t, nil
}
