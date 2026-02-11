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

// Challenge 额外身份验证步骤的临时会话状态（三层模型）
// 验证通过后签发 ChallengeToken，此记录即可删除
type Challenge struct {
	ID          string         `json:"id"`
	ClientID    string         `json:"client_id"`         // 发起验证的应用 ID
	Audience    string         `json:"audience"`          // 目标服务 ID
	Type        string         `json:"type,omitempty"`    // 业务场景（login / forget_password / bind_phone，验证类必填，交换类为空）
	ChannelType ChannelType    `json:"channel_type"`      // 验证方式（email_otp / totp / sms_otp / webauthn / captcha / wechat-mp ...）
	Channel     string         `json:"channel,omitempty"` // 验证目标（邮箱 / 手机号 / user_id / wx_code ...）
	CreatedAt   time.Time      `json:"created_at"`
	ExpiresAt   time.Time      `json:"expires_at"`
	Data        map[string]any `json:"data,omitempty"` // 临时验证数据（如 masked_email、session 等）
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
