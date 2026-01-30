// Package types provides type definitions for the Auth module.
// nolint:revive // This package name follows Go conventions for internal type packages.
package types

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

// ChallengeType Challenge 类型
type ChallengeType string

const (
	ChallengeTypeCaptcha ChallengeType = "captcha" // 人机验证（Turnstile）
	ChallengeTypeTOTP    ChallengeType = "totp"    // TOTP 动态口令
	ChallengeTypeEmail   ChallengeType = "email"   // 邮箱验证码
)

// Challenge 额外的身份验证步骤
type Challenge struct {
	ID        string         `json:"id"`
	FlowID    string         `json:"flow_id,omitempty"`    // 关联的 AuthFlow ID（可选）
	UserID    string         `json:"user_id,omitempty"`    // 关联的用户 ID（可选）
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

// GenerateChallengeID 生成 Challenge ID
func GenerateChallengeID() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "ch_" + hex.EncodeToString([]byte(time.Now().Format("20060102150405.000000000")))
	}
	return "ch_" + hex.EncodeToString(bytes)
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
	case ChallengeTypeEmail:
		return true // email 需要 captcha 前置
	default:
		return false
	}
}
