// Package challenge provides challenge verification service.
package challenge

import (
	"github.com/heliannuuthus/helios/internal/aegis/types"
)

// CreateRequest 创建 Challenge 请求
type CreateRequest struct {
	Type         types.ChallengeType `json:"type" binding:"required,oneof=captcha email-otp totp sms-otp tg-otp"`
	UserID       string              `json:"user_id,omitempty"`       // TOTP 类型时必填（用于查找 TOTP secret）
	Email        string              `json:"email,omitempty"`         // email-otp 类型时必填
	Phone        string              `json:"phone,omitempty"`         // sms-otp 类型时必填
	CaptchaToken string              `json:"captcha_token,omitempty"` // captcha 前置验证 token（正常用户静默获取）
}

// CreateResponse 创建 Challenge 响应
type CreateResponse struct {
	ChallengeID string             `json:"challenge_id"`
	Type        string             `json:"type,omitempty"`       // 有 required 时不返回
	ExpiresIn   int                `json:"expires_in,omitempty"` // 有 required 时不返回
	Data        map[string]any     `json:"data,omitempty"`
	Required    *types.VChanConfig `json:"required,omitempty"` // 需要先完成的前置验证（复用 VChanConfig）
}

// VerifyRequest 验证 Challenge 请求（challenge_id 从 query 获取）
type VerifyRequest struct {
	Proof any `json:"proof" binding:"required"` // 验证证明（string: captcha token / OTP code, object: WebAuthn assertion）
}

// VerifyResponse 验证 Challenge 响应
type VerifyResponse struct {
	Verified       bool           `json:"verified"`
	ChallengeID    string         `json:"challenge_id,omitempty"`    // 后续 challenge ID（captcha 验证后创建的 email challenge）
	ChallengeToken string         `json:"challenge_token,omitempty"` // 验证成功后的凭证（用于 Login 的 proof）
	Data           map[string]any `json:"data,omitempty"`            // 附加数据
}
