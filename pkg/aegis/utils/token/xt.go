package token

import (
	"fmt"
	"time"

	"aidanwoods.dev/go-paseto"
)

// ChannelType 验证方式（系统定义）
// 命名规范：{delivery}_{method}（如 email_otp, sms_otp），与数据库及前端保持一致
type ChannelType string

const (
	// 非认证因子（前置条件）
	ChannelTypeCaptcha ChannelType = "captcha" // 人机验证（Turnstile）

	// 验证类（支持 Type 业务场景配置）
	ChannelTypeEmailOTP ChannelType = "email_otp" // 邮箱 OTP
	ChannelTypeTOTP     ChannelType = "totp"      // TOTP 动态口令（Authenticator App）
	ChannelTypeSmsOTP   ChannelType = "sms_otp"   // 短信 OTP
	ChannelTypeTgOTP    ChannelType = "tg_otp"    // Telegram OTP
	ChannelTypeWebAuthn ChannelType = "webauthn"  // WebAuthn/Passkey

	// 交换类（平台固定能力，不需要 Type）
	ChannelTypeWechatMP ChannelType = "wechat-mp" // 微信小程序换手机号
	ChannelTypeAlipayMP ChannelType = "alipay-mp" // 支付宝小程序换手机号
)

// IsVerification 检查是否是验证类 ChannelType（排除 captcha 和交换类）
func (t ChannelType) IsVerification() bool {
	switch t {
	case ChannelTypeEmailOTP, ChannelTypeTOTP, ChannelTypeSmsOTP, ChannelTypeTgOTP, ChannelTypeWebAuthn:
		return true
	default:
		return false
	}
}

// IsExchange 检查是否是交换类 ChannelType
func (t ChannelType) IsExchange() bool {
	switch t {
	case ChannelTypeWechatMP, ChannelTypeAlipayMP:
		return true
	default:
		return false
	}
}

// ChallengeToken Challenge 验证令牌
// 用于证明某个 principal 已完成特定的身份验证挑战
//
// 设计说明：
// - sub: 完成验证的 principal
//   - email_otp → 邮箱地址
//   - sms_otp → 手机号
//   - totp → 用户 OpenID
//   - webauthn → credential ID
//   - wechat-mp → 手机号（交换得到）
//
// - typ: 业务类型（如 staff:verify / user:verify，交换类为空）
// - aud: 目标服务 ID
// - cli: 发起验证的应用 ID
type ChallengeToken struct {
	Claims         // 内嵌基础 Claims
	subject string // sub - 完成验证的 principal
	typ     string // typ - 业务类型
}

// ==================== XT TokenTypeBuilder ====================

// XT ChallengeToken 类型构建器，实现 TokenTypeBuilder 接口
type XT struct {
	subject string
	typ     string
}

func NewChallengeTokenBuilder() *XT {
	return &XT{}
}

func (x *XT) Subject(subject string) *XT {
	x.subject = subject
	return x
}

func (x *XT) Type(typ string) *XT {
	x.typ = typ
	return x
}

func (x *XT) Build(claims Claims) Token {
	return &ChallengeToken{
		Claims:  claims,
		subject: x.subject,
		typ:     x.typ,
	}
}

// ==================== 解析函数 ====================

// ParseChallengeToken 从 PASETO Token 解析 ChallengeToken
func ParseChallengeToken(pasetoToken *paseto.Token) (*ChallengeToken, error) {
	claims, err := ParseClaims(pasetoToken)
	if err != nil {
		return nil, fmt.Errorf("parse claims: %w", err)
	}

	subject, err := pasetoToken.GetSubject()
	if err != nil {
		return nil, fmt.Errorf("get subject: %w", err)
	}

	var typ string
	if err := pasetoToken.Get(ClaimType, &typ); err != nil {
		typ = ""
	}

	return &ChallengeToken{
		Claims:  claims,
		subject: subject,
		typ:     typ,
	}, nil
}

// ==================== Token 接口实现 ====================

// Type 实现 Token 接口
func (c *ChallengeToken) Type() TokenType {
	return TokenTypeChallenge
}

// build 实现 tokenBuilder 接口
func (c *ChallengeToken) build() (*paseto.Token, error) {
	return c.BuildPaseto()
}

// BuildPaseto 构建 PASETO Token（不包含签名）
func (c *ChallengeToken) BuildPaseto() (*paseto.Token, error) {
	t := paseto.NewToken()
	if err := c.SetStandardClaims(&t); err != nil {
		return nil, fmt.Errorf("set standard claims: %w", err)
	}
	t.SetSubject(c.subject)
	if c.typ != "" {
		if err := t.Set(ClaimType, c.typ); err != nil {
			return nil, fmt.Errorf("set typ: %w", err)
		}
	}
	return &t, nil
}

// ExpiresIn 返回过期时间
func (c *ChallengeToken) ExpiresIn() time.Duration {
	return c.GetExpiresIn()
}

// GetSubject 返回 principal
func (c *ChallengeToken) GetSubject() string {
	return c.subject
}

// GetType 返回业务类型
func (c *ChallengeToken) GetType() string {
	return c.typ
}
