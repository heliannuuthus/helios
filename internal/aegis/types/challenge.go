// Package types provides type definitions for the Auth module.
// nolint:revive // This package name follows Go conventions for internal type packages.
package types

import (
	"time"

	"github.com/heliannuuthus/helios/pkg/utils"
)

// ChallengeType Challenge 类型
// 命名规范：{channel}-{method}，与 MFA 配置保持一致
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

// Challenge 额外的身份验证步骤
type Challenge struct {
	ID        string         `json:"id"`
	FlowID    string         `json:"flow_id,omitempty"` // 关联的 AuthFlow ID（可选）
	UserID    string         `json:"user_id,omitempty"` // 关联的用户 ID（可选）
	Type      ChallengeType  `json:"type"`
	CreatedAt time.Time      `json:"created_at"`
	ExpiresAt time.Time      `json:"expires_at"`
	Verified  bool           `json:"verified"`
	Data      map[string]any `json:"data,omitempty"` // 附加数据（如 masked_email）
}

// IsExpired 检查是否已过期
func (c *Challenge) IsExpired() bool {
	return time.Now().After(c.ExpiresAt)
}

// IsValid 检查是否有效（未过期且未验证）
func (c *Challenge) IsValid() bool {
	return !c.IsExpired() && !c.Verified
}

// GenerateChallengeID 生成 Challenge ID（16位 Base62）
func GenerateChallengeID() string {
	return utils.GenerateID(16)
}

// NewChallenge 创建新的 Challenge
func NewChallenge(challengeType ChallengeType, ttl time.Duration) *Challenge {
	now := time.Now()
	return &Challenge{
		ID:        GenerateChallengeID(),
		Type:      challengeType,
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
		Verified:  false,
	}
}

// SetVerified 设置为已验证
func (c *Challenge) SetVerified() {
	c.Verified = true
}

// SetData 设置附加数据
func (c *Challenge) SetData(key string, value any) {
	if c.Data == nil {
		c.Data = make(map[string]any)
	}
	c.Data[key] = value
}

// GetData 获取附加数据
func (c *Challenge) GetData(key string) (any, bool) {
	if c.Data == nil {
		return nil, false
	}
	v, ok := c.Data[key]
	return v, ok
}

// GetStringData 获取字符串类型的附加数据
func (c *Challenge) GetStringData(key string) string {
	v, ok := c.GetData(key)
	if !ok {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

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
