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

// RequiresCaptcha 检查该 ChannelType 是否需要 Captcha 前置验证
func (t ChannelType) RequiresCaptcha() bool {
	switch t {
	case ChannelTypeEmailOTP, ChannelTypeSmsOTP:
		return true
	default:
		return false
	}
}

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
// - typ: ChannelType（验证方式）
// - biz: 业务场景（login / forget_password，交换类为空）
// - aud: 目标服务 ID
// - cli: 发起验证的应用 ID
type ChallengeToken struct {
	Claims                  // 内嵌基础 Claims
	subject     string      // sub - 完成验证的 principal
	channelType ChannelType // typ - 验证方式
	bizType     string      // biz - 业务场景
}

// ==================== Challenge TokenTypeBuilder ====================

// Challenge Challenge 类型构建器，实现 TokenTypeBuilder 接口
type Challenge struct {
	subject     string
	channelType ChannelType
	bizType     string
}

// NewChallengeTokenBuilder 创建 Challenge 类型构建器
func NewChallengeTokenBuilder() *Challenge {
	return &Challenge{}
}

// Subject 设置完成验证的 principal
func (c *Challenge) Subject(subject string) *Challenge {
	c.subject = subject
	return c
}

// Type 设置验证方式（ChannelType）
func (c *Challenge) Type(channelType ChannelType) *Challenge {
	c.channelType = channelType
	return c
}

// BizType 设置业务场景
func (c *Challenge) BizType(bizType string) *Challenge {
	c.bizType = bizType
	return c
}

// build 实现 TokenTypeBuilder 接口
func (c *Challenge) build(claims Claims) Token {
	return &ChallengeToken{
		Claims:      claims,
		subject:     c.subject,
		channelType: c.channelType,
		bizType:     c.bizType,
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

	var channelType string
	if err := pasetoToken.Get(ClaimType, &channelType); err != nil {
		return nil, fmt.Errorf("get typ: %w", err)
	}

	var bizType string
	if err := pasetoToken.Get(ClaimBizType, &bizType); err != nil {
		// bizType 是可选字段（交换类 Challenge 不包含），忽略错误
		bizType = ""
	}

	return &ChallengeToken{
		Claims:      claims,
		subject:     subject,
		channelType: ChannelType(channelType),
		bizType:     bizType,
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
	if err := t.Set(ClaimType, c.channelType); err != nil {
		return nil, fmt.Errorf("set typ: %w", err)
	}
	if c.bizType != "" {
		if err := t.Set(ClaimBizType, c.bizType); err != nil {
			return nil, fmt.Errorf("set biz: %w", err)
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

// GetChannelType 返回验证方式
func (c *ChallengeToken) GetChannelType() ChannelType {
	return c.channelType
}

// GetBizType 返回业务场景
func (c *ChallengeToken) GetBizType() string {
	return c.bizType
}
