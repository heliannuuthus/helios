// Package challenge provides challenge verification service.
package challenge

import (
	"github.com/heliannuuthus/helios/internal/aegis/types"
)

// CreateRequest 创建 Challenge 请求（三层模型：type / channel_type / channel）
type CreateRequest struct {
	ClientID    string            `json:"client_id" binding:"required"`                                                      // 应用 ID
	Audience    string            `json:"audience" binding:"required"`                                                       // 目标服务 ID
	Type        string            `json:"type,omitempty"`                                                                    // 业务场景（验证类必填，交换类忽略）
	ChannelType types.ChannelType `json:"channel_type" binding:"required,oneof=email_otp totp webauthn wechat-mp alipay-mp"` // 验证方式
	Channel     string            `json:"channel" binding:"required"`                                                        // 验证目标（邮箱 / 手机号 / user_id / wx_code ...）
}

// CreateResponse 创建 Challenge 响应
type CreateResponse struct {
	ChallengeID string                  `json:"challenge_id"`
	ChannelType string                  `json:"channel_type,omitempty"` // 有 required 时不返回
	ExpiresIn   int                     `json:"expires_in,omitempty"`   // 有 required 时不返回
	Data        map[string]any          `json:"data,omitempty"`
	Required    *types.ConnectionConfig `json:"required,omitempty"` // 需要先完成的前置验证
	Token       string                  `json:"token,omitempty"`    // 交换类直接返回 ChallengeToken（由 handler 填充）
}

// VerifyRequest 验证 Challenge 请求（challenge_id 从 query 获取）
type VerifyRequest struct {
	ChannelType string `json:"channel_type" binding:"required"` // 本次验证的方式（captcha / email_otp / totp ...）
	Proof       any    `json:"proof" binding:"required"`        // 验证证明
}

// VerifyResult service 层返回的验证结果（不含 Token，Token 由 handler 签发）
type VerifyResult struct {
	Verified  bool             // 是否验证成功
	Challenge *types.Challenge // 验证成功时返回 Challenge 信息（供 handler 签发 Token）
	// 前置验证（captcha 通过后）
	ChallengeID string         // 前置验证通过后返回的 challenge_id
	Data        map[string]any // 附加数据（如 next channel_type）
}

// VerifyResponse handler 层返回给前端的 HTTP 响应
type VerifyResponse struct {
	Verified       bool           `json:"verified"`
	ChallengeID    string         `json:"challenge_id,omitempty"`    // challenge ID（前置验证通过后返回）
	ChallengeToken string         `json:"challenge_token,omitempty"` // 验证成功后的凭证（handler 签发）
	Data           map[string]any `json:"data,omitempty"`
}
