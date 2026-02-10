package token

import (
	"fmt"
	"time"

	"aidanwoods.dev/go-paseto"
)

// ChallengeType Challenge 类型
// 命名规范：{delivery}-{method}（如 email-otp, sms-otp），与 MFA 配置保持一致
type ChallengeType string

const (
	// VChan 类型（验证渠道，非 MFA）
	ChallengeTypeCaptcha ChallengeType = "captcha" // 人机验证（Turnstile）

	// MFA 类型（多因素认证）
	ChallengeTypeEmailOTP ChallengeType = "email-otp" // 邮箱 OTP
	ChallengeTypeTOTP     ChallengeType = "totp"      // TOTP 动态口令（Authenticator App）
	ChallengeTypeSmsOTP   ChallengeType = "sms-otp"   // 短信 OTP（预留）
	ChallengeTypeTgOTP    ChallengeType = "tg-otp"    // Telegram OTP（预留）
	ChallengeTypeWebAuthn ChallengeType = "webauthn"  // WebAuthn/Passkey
)

// RequiresCaptcha 检查该 Challenge 类型是否需要 Captcha 前置验证
func (t ChallengeType) RequiresCaptcha() bool {
	switch t {
	case ChallengeTypeEmailOTP, ChallengeTypeSmsOTP:
		return true // 发送类 OTP 需要 captcha 前置防刷
	default:
		return false
	}
}

// IsMFA 检查是否是 MFA 类型
func (t ChallengeType) IsMFA() bool {
	switch t {
	case ChallengeTypeEmailOTP, ChallengeTypeTOTP, ChallengeTypeSmsOTP, ChallengeTypeTgOTP, ChallengeTypeWebAuthn:
		return true
	default:
		return false
	}
}

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
	Claims                      // 内嵌基础 Claims
	subject       string        // sub - 完成挑战的 principal（如 email、phone、credential_id）
	challengeType ChallengeType // typ - Challenge 类型
}

// ==================== Challenge TokenTypeBuilder ====================

// Challenge Challenge 类型构建器，实现 TokenTypeBuilder 接口
type Challenge struct {
	subject       string
	challengeType ChallengeType
}

// NewChallengeTokenBuilder 创建 Challenge 类型构建器
func NewChallengeTokenBuilder() *Challenge {
	return &Challenge{}
}

// Subject 设置完成挑战的 principal
func (c *Challenge) Subject(subject string) *Challenge {
	c.subject = subject
	return c
}

// Type 设置挑战类型
func (c *Challenge) Type(challengeType ChallengeType) *Challenge {
	c.challengeType = challengeType
	return c
}

// build 实现 TokenTypeBuilder 接口
func (c *Challenge) build(claims Claims) Token {
	return &ChallengeToken{
		Claims:        claims,
		subject:       c.subject,
		challengeType: c.challengeType,
	}
}

// ==================== 解析函数 ====================

// ParseChallengeToken 从 PASETO Token 解析 ChallengeToken（用于验证后）
func ParseChallengeToken(pasetoToken *paseto.Token) (*ChallengeToken, error) {
	claims, err := ParseClaims(pasetoToken)
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
		challengeType: ChallengeType(challengeType),
	}, nil
}

// ==================== Token 接口实现 ====================

// Type 实现 Token 接口
func (c *ChallengeToken) Type() TokenType {
	return TokenTypeChallenge
}

// build 实现 tokenBuilder 接口（小写，内部使用）
func (c *ChallengeToken) build() (*paseto.Token, error) {
	return c.BuildPaseto()
}

// BuildPaseto 构建 PASETO Token（不包含签名）
func (c *ChallengeToken) BuildPaseto() (*paseto.Token, error) {
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
func (c *ChallengeToken) GetChallengeType() ChallengeType {
	return c.challengeType
}
