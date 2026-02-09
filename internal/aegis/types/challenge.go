// Package types provides type definitions for the Auth module.
// nolint:revive // This package name follows Go conventions for internal type packages.
package types

import (
	"time"

	"github.com/heliannuuthus/helios/pkg/aegis/token"
	"github.com/heliannuuthus/helios/pkg/helperutil"
)

// ChallengeType 是 token.ChallengeType 的别名
type ChallengeType = token.ChallengeType

// 常量别名 - 从 pkg/aegis/token 导入
const (
	ChallengeTypeCaptcha  = token.ChallengeTypeCaptcha
	ChallengeTypeEmailOTP = token.ChallengeTypeEmailOTP
	ChallengeTypeTOTP     = token.ChallengeTypeTOTP
	ChallengeTypeSmsOTP   = token.ChallengeTypeSmsOTP
	ChallengeTypeTgOTP    = token.ChallengeTypeTgOTP
	ChallengeTypeWebAuthn = token.ChallengeTypeWebAuthn
)

// Challenge 额外身份验证步骤的临时会话状态
// 验证通过后签发 PASETO ChallengeToken，此记录即可删除
type Challenge struct {
	ID        string         `json:"id"`
	Type      ChallengeType  `json:"type"`
	CreatedAt time.Time      `json:"created_at"`
	ExpiresAt time.Time      `json:"expires_at"`
	Data      map[string]any `json:"data,omitempty"` // 临时验证数据（如 email、OTP secret 等）
}

// IsExpired 检查是否已过期
func (c *Challenge) IsExpired() bool {
	return time.Now().After(c.ExpiresAt)
}

// GenerateChallengeID 生成 Challenge ID（16位 Base62）
func GenerateChallengeID() string {
	return helperutil.GenerateID(16)
}

// NewChallenge 创建新的 Challenge
func NewChallenge(challengeType ChallengeType, ttl time.Duration) *Challenge {
	now := time.Now()
	return &Challenge{
		ID:        GenerateChallengeID(),
		Type:      challengeType,
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
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
