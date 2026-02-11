// Package challenge provides challenge verification service.
package challenge

import (
	"github.com/heliannuuthus/helios/internal/aegis/types"
)

// CaptchaConfig 是 types.CaptchaConfig 的别名
type CaptchaConfig = types.CaptchaConfig

// ChallengeRequired 是 types.CaptchaRequired 的别名
// Verified 是内部状态（序列化到 Redis），不暴露给客户端（通过 ForClient 隐藏）
type ChallengeRequired = types.CaptchaRequired

// ==================== Create ====================

// CreateRequest 创建 Challenge 请求（三层模型：type / channel_type / channel）
type CreateRequest struct {
	ClientID    string `json:"client_id" binding:"required"`                                                      // 应用 ID
	Audience    string `json:"audience" binding:"required"`                                                       // 目标服务 ID
	Type        string `json:"type,omitempty"`                                                                    // 业务场景（验证类必填，交换类忽略）
	ChannelType string `json:"channel_type" binding:"required,oneof=email_otp totp webauthn wechat-mp alipay-mp"` // 验证方式
	Channel     string `json:"channel" binding:"required"`                                                        // 验证目标（邮箱 / 手机号 / user_id / wx_code ...）
}

// CreateResponse 创建 Challenge 响应
type CreateResponse struct {
	ChallengeID string             `json:"challenge_id"`
	Required    *ChallengeRequired `json:"required,omitempty"`    // 前置条件
	RetryAfter  int                `json:"retry_after,omitempty"` // 限流，下次可发起的秒数
}

// ==================== Verify ====================

// VerifyRequest 验证 Challenge 请求（challenge_id 从 path 获取）
type VerifyRequest struct {
	Type  string `json:"type,omitempty"`           // captcha provider 类型（如 "turnstile"），仅 captcha 验证时传
	Proof any    `json:"proof" binding:"required"` // 验证证明
}

// VerifyResult service 层返回的验证结果（不含 Token，Token 由 handler 签发）
type VerifyResult struct {
	Verified   bool               // 是否验证成功
	Challenge  *types.Challenge   // 验证成功时返回 Challenge 信息（供 handler 签发 Token）
	Required   *ChallengeRequired // 前置未完成时返回（引导前端渲染）
	RetryAfter int                // 限流，下次可发起的秒数
}

// VerifyResponse handler 层返回给前端的 HTTP 响应
type VerifyResponse struct {
	Verified       bool               `json:"verified"`
	ChallengeToken string             `json:"challenge_token,omitempty"` // 验证成功后的凭证（handler 签发）
	Required       *ChallengeRequired `json:"required,omitempty"`        // 前置未完成时引导渲染
	RetryAfter     int                `json:"retry_after,omitempty"`     // 限流
}
