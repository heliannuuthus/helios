// Package types provides type definitions for the Auth module.
// nolint:revive // This package name follows Go conventions for internal type packages.
package types

import (
	"time"

	"github.com/heliannuuthus/helios/pkg/aegis/token"
	"github.com/heliannuuthus/helios/pkg/helperutil"
)

// ChannelType 是 token.ChannelType 的别名
type ChannelType = token.ChannelType

// 常量别名 - 从 pkg/aegis/token 导入
const (
	ChannelTypeCaptcha  = token.ChannelTypeCaptcha
	ChannelTypeEmailOTP = token.ChannelTypeEmailOTP
	ChannelTypeTOTP     = token.ChannelTypeTOTP
	ChannelTypeSmsOTP   = token.ChannelTypeSmsOTP
	ChannelTypeTgOTP    = token.ChannelTypeTgOTP
	ChannelTypeWebAuthn = token.ChannelTypeWebAuthn
	ChannelTypeWechatMP = token.ChannelTypeWechatMP
	ChannelTypeAlipayMP = token.ChannelTypeAlipayMP
)

// CaptchaConfig 人机验证配置（前端据此渲染 captcha 组件）
type CaptchaConfig struct {
	Strategy   []string `json:"strategy"`   // 可用的 captcha provider（如 ["turnstile"]）
	Identifier string   `json:"identifier"` // 站点公钥（site_key）
}

// CaptchaRequired captcha 前置条件（序列化到 Redis）
// Verified 是内部状态，不暴露给客户端（通过 ForClient 隐藏）
type CaptchaRequired struct {
	Captcha  *CaptchaConfig `json:"captcha,omitempty"`  // 人机验证配置
	Verified bool           `json:"verified,omitempty"` // captcha 是否已验证（内部状态）
}

// ForClient 返回客户端安全的副本（隐藏 Verified 内部状态）
// Verified 为零值 + omitempty，JSON 序列化时不会出现
func (r *CaptchaRequired) ForClient() *CaptchaRequired {
	if r == nil {
		return nil
	}
	return &CaptchaRequired{
		Captcha: r.Captcha,
	}
}

// Challenge 额外身份验证步骤的临时会话状态（三层模型）
// 验证通过后签发 ChallengeToken，此记录即可删除
type Challenge struct {
	ID          string           `json:"id"`
	ClientID    string           `json:"client_id"`          // 发起验证的应用 ID
	Audience    string           `json:"audience"`           // 目标服务 ID
	Type        string           `json:"type,omitempty"`     // 业务场景（login / forget_password / bind_phone，验证类必填，交换类为空）
	ChannelType ChannelType      `json:"channel_type"`       // 验证方式（email_otp / totp / sms_otp / webauthn / captcha / wechat-mp ...）
	Channel     string           `json:"channel,omitempty"`  // 验证目标（邮箱 / 手机号 / user_id / wx_code ...）
	Required    *CaptchaRequired `json:"required,omitempty"` // captcha 前置条件状态
	CreatedAt   time.Time        `json:"created_at"`
	ExpiresAt   time.Time        `json:"expires_at"`
	Data        map[string]any   `json:"data,omitempty"` // 临时验证数据（如 masked_email、session 等）
}

// NeedsCaptcha 检查是否需要先完成 captcha 验证
func (c *Challenge) NeedsCaptcha() bool {
	return c.Required != nil && c.Required.Captcha != nil && !c.Required.Verified
}

// IsExpired 检查是否已过期
func (c *Challenge) IsExpired() bool {
	return time.Now().After(c.ExpiresAt)
}

// GenerateChallengeID 生成 Challenge ID（16位 Base62）
func GenerateChallengeID() string {
	return helperutil.GenerateID(16)
}

// NewChallenge 创建新的 Challenge（三层模型）
func NewChallenge(clientID, audience, bizType string, channelType ChannelType, channel string, ttl time.Duration) *Challenge {
	now := time.Now()
	return &Challenge{
		ID:          GenerateChallengeID(),
		ClientID:    clientID,
		Audience:    audience,
		Type:        bizType,
		ChannelType: channelType,
		Channel:     channel,
		CreatedAt:   now,
		ExpiresAt:   now.Add(ttl),
	}
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
