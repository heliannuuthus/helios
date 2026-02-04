package token

import (
	"fmt"
	"time"

	"aidanwoods.dev/go-paseto"

	"github.com/heliannuuthus/helios/internal/aegis/types"
	"github.com/heliannuuthus/helios/pkg/aegis/token"
)

// ChallengeToken Challenge 验证令牌
// 用于证明某个 principal 已完成特定的身份验证挑战（如 MFA、邮箱验证等）
// 该令牌短期有效，用于后续流程的验证
//
// 设计说明：
// - sub: 完成挑战的 principal（凭证标识）
//   - email-otp → 邮箱地址
//   - sms-otp → 手机号
//   - totp → 用户 OpenID（TOTP 绑定在用户上）
//   - webauthn → credential ID
//
// - typ: Challenge 类型（如 email-otp、totp、webauthn）
// - aud: 目标服务 ID
// - cli: 发起挑战的应用 ID
type ChallengeToken struct {
	token.Claims                      // 内嵌基础 Claims
	subject       string              // sub - 完成挑战的 principal（如 email、phone、credential_id）
	challengeType types.ChallengeType // typ - Challenge 类型
}

// NewChallengeToken 创建 ChallengeToken（用于签发）
// subject: 完成挑战的 principal（如 email、phone、credential_id）
// challengeType: 挑战类型（如 email-otp、totp、webauthn）
func NewChallengeToken(
	issuer, subject, audience, clientID string,
	challengeType types.ChallengeType,
	expiresIn time.Duration,
) *ChallengeToken {
	return &ChallengeToken{
		Claims:        token.NewClaims(issuer, clientID, audience, expiresIn),
		subject:       subject,
		challengeType: challengeType,
	}
}

// parseChallengeToken 从 PASETO Token 解析 ChallengeToken（用于验证后）
func parseChallengeToken(pasetoToken *paseto.Token) (*ChallengeToken, error) {
	claims, err := token.ParseClaims(pasetoToken)
	if err != nil {
		return nil, fmt.Errorf("parse claims: %w", err)
	}

	subject, err := pasetoToken.GetSubject()
	if err != nil {
		return nil, fmt.Errorf("get subject: %w", err)
	}

	var challengeType string
	if err := pasetoToken.Get("typ", &challengeType); err != nil {
		return nil, fmt.Errorf("get typ: %w", err)
	}

	return &ChallengeToken{
		Claims:        claims,
		subject:       subject,
		challengeType: types.ChallengeType(challengeType),
	}, nil
}

// Build 构建 PASETO Token（不包含签名）
func (c *ChallengeToken) Build() (*paseto.Token, error) {
	t := paseto.NewToken()
	if err := c.SetStandardClaims(&t); err != nil {
		return nil, fmt.Errorf("set standard claims: %w", err)
	}
	t.SetSubject(c.subject) // sub = principal（email、phone、credential_id 等）
	if err := t.Set("typ", c.challengeType); err != nil {
		return nil, fmt.Errorf("set typ: %w", err)
	}
	return &t, nil
}

// ExpiresIn 实现 AccessToken 接口
func (c *ChallengeToken) ExpiresIn() time.Duration {
	return c.GetExpiresIn()
}

// GetSubject 返回 principal（如 email、phone、credential_id）
func (c *ChallengeToken) GetSubject() string {
	return c.subject
}

// GetChallengeType 返回 Challenge 类型
func (c *ChallengeToken) GetChallengeType() types.ChallengeType {
	return c.challengeType
}
