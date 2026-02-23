// Package types provides type definitions for the Auth module.
// nolint:revive // This package name follows Go conventions for internal type packages.
package types

import (
	"github.com/go-json-experiment/json"
	"time"

	"github.com/heliannuuthus/helios/pkg/aegis/token"
	"github.com/heliannuuthus/helios/pkg/helpers"
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

// ChallengeRequiredConfig 前置条件配置
// 响应序列化时不输出 Verified，Redis 序列化时输出
type ChallengeRequiredConfig struct {
	Identifier string   `json:"identifier,omitempty"` // 公开标识（site_key）
	Strategy   []string `json:"strategy,omitempty"`   // 认证方式（如 turnstile）
	Verified   bool     `json:"-"`                    // 是否已验证通过（响应不输出）
}

// challengeRequiredConfigFull 用于 Redis 序列化（包含 Verified）
type challengeRequiredConfigFull struct {
	Identifier string   `json:"identifier,omitempty"`
	Strategy   []string `json:"strategy,omitempty"`
	Verified   bool     `json:"verified,omitempty"`
}

// ChallengeRequired 前置条件
// 自定义序列化：响应不含 verified，Redis 含 verified
type ChallengeRequired map[string]*ChallengeRequiredConfig

// MarshalJSON 响应序列化（不含 Verified）
func (r ChallengeRequired) MarshalJSON() ([]byte, error) {
	if r == nil {
		return []byte("null"), nil
	}
	resp := make(map[string]*ChallengeRequiredConfig, len(r))
	for k, v := range r {
		resp[k] = v
	}
	type plain map[string]*ChallengeRequiredConfig
	return json.Marshal(plain(resp))
}

// GetConnection 获取前置条件的 connection 名
func (r ChallengeRequired) GetConnection() string {
	for conn := range r {
		return conn
	}
	return ""
}

// GetConfig 获取前置条件的配置
func (r ChallengeRequired) GetConfig() *ChallengeRequiredConfig {
	for _, cfg := range r {
		return cfg
	}
	return nil
}

// Contains 检查是否包含指定的前置条件类型
func (r ChallengeRequired) Contains(reqType string) bool {
	_, ok := r[reqType]
	return ok
}

// Challenge 额外身份验证步骤的临时会话状态（三层模型）
// 验证通过后签发 ChallengeToken，此记录即可删除
type Challenge struct {
	ID          string            `json:"id"`
	ClientID    string            `json:"client_id"`          // 发起验证的应用 ID
	Audience    string            `json:"audience"`           // 目标服务 ID
	Type        string            `json:"type,omitempty"`     // 业务场景（login / forget_password / bind_phone，验证类必填，交换类为空）
	ChannelType ChannelType       `json:"channel_type"`       // 验证方式（email_otp / totp / sms_otp / webauthn / captcha / wechat-mp ...）
	Channel     string            `json:"channel,omitempty"`  // 验证目标（邮箱 / 手机号 / user_id / wx_code ...）
	Required    ChallengeRequired `json:"required,omitempty"` // 前置条件（如 captcha）
	Limits      map[string]int    `json:"limits,omitempty"`   // 限流配置（从 ServiceChallengeSetting 复制）
	IP          string            `json:"ip,omitempty"`       // 客户端 IP（用于 IP 维度限流）
	CreatedAt   time.Time         `json:"created_at"`
	ExpiresAt   time.Time         `json:"expires_at"`
	Data        map[string]any    `json:"data,omitempty"` // 临时验证数据（如 masked_email、session 等）
}

// IsUnmet 检查是否有未完成的前置条件
func (c *Challenge) IsUnmet() bool {
	for _, cfg := range c.Required {
		if !cfg.Verified {
			return true
		}
	}
	return false
}

// IsExpired 检查是否已过期
func (c *Challenge) IsExpired() bool {
	return time.Now().After(c.ExpiresAt)
}

// ExpiresIn 返回剩余有效时间
func (c *Challenge) ExpiresIn() time.Duration {
	return time.Until(c.ExpiresAt)
}

// GenerateChallengeID 生成 Challenge ID（16位 Base62）
func GenerateChallengeID() string {
	return helpers.GenerateID(16)
}

// NewChallenge 创建新的 Challenge（三层模型）
func NewChallenge(clientID, audience, bizType string, channelType ChannelType, channel string, expiresIn time.Duration, limits map[string]int, ip string) *Challenge {
	now := time.Now()
	return &Challenge{
		ID:          GenerateChallengeID(),
		ClientID:    clientID,
		Audience:    audience,
		Type:        bizType,
		ChannelType: channelType,
		Channel:     channel,
		Limits:      limits,
		IP:          ip,
		CreatedAt:   now,
		ExpiresAt:   now.Add(expiresIn),
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

// challengeStorage Redis 序列化用的内部结构（含 Required.Verified）
type challengeStorage struct {
	ID          string                              `json:"id"`
	ClientID    string                              `json:"client_id"`
	Audience    string                              `json:"audience"`
	Type        string                              `json:"type,omitempty"`
	ChannelType ChannelType                         `json:"channel_type"`
	Channel     string                              `json:"channel,omitempty"`
	Required    map[string]*challengeRequiredConfigFull `json:"required,omitempty"`
	Limits      map[string]int                      `json:"limits,omitempty"`
	IP          string                              `json:"ip,omitempty"`
	CreatedAt   time.Time                           `json:"created_at"`
	ExpiresAt   time.Time                           `json:"expires_at"`
	Data        map[string]any                      `json:"data,omitempty"`
}

// MarshalForStorage Redis 序列化（含 Required.Verified）
func (c *Challenge) MarshalForStorage() ([]byte, error) {
	var required map[string]*challengeRequiredConfigFull
	if c.Required != nil {
		required = make(map[string]*challengeRequiredConfigFull, len(c.Required))
		for k, v := range c.Required {
			required[k] = &challengeRequiredConfigFull{
				Identifier: v.Identifier,
				Strategy:   v.Strategy,
				Verified:   v.Verified,
			}
		}
	}
	return json.Marshal(&challengeStorage{
		ID:          c.ID,
		ClientID:    c.ClientID,
		Audience:    c.Audience,
		Type:        c.Type,
		ChannelType: c.ChannelType,
		Channel:     c.Channel,
		Required:    required,
		Limits:      c.Limits,
		IP:          c.IP,
		CreatedAt:   c.CreatedAt,
		ExpiresAt:   c.ExpiresAt,
		Data:        c.Data,
	})
}

// UnmarshalFromStorage Redis 反序列化（含 Required.Verified）
func (c *Challenge) UnmarshalFromStorage(data []byte) error {
	var s challengeStorage
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	c.ID = s.ID
	c.ClientID = s.ClientID
	c.Audience = s.Audience
	c.Type = s.Type
	c.ChannelType = s.ChannelType
	c.Channel = s.Channel
	c.Limits = s.Limits
	c.IP = s.IP
	c.CreatedAt = s.CreatedAt
	c.ExpiresAt = s.ExpiresAt
	c.Data = s.Data
	if s.Required != nil {
		c.Required = make(ChallengeRequired, len(s.Required))
		for k, v := range s.Required {
			c.Required[k] = &ChallengeRequiredConfig{
				Identifier: v.Identifier,
				Strategy:   v.Strategy,
				Verified:   v.Verified,
			}
		}
	}
	return nil
}
