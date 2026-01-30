// Package challenge provides challenge verification service.
package challenge

import (
	"github.com/heliannuuthus/helios/internal/aegis/types"
)

// CreateRequest 创建 Challenge 请求
type CreateRequest struct {
	Type         types.ChallengeType `json:"type" binding:"required,oneof=captcha totp email"`
	FlowID       string              `json:"flow_id,omitempty"`       // 关联的 AuthFlow ID
	UserID       string              `json:"user_id,omitempty"`       // 关联的用户 ID
	Email        string              `json:"email,omitempty"`         // email 类型时必填
	CaptchaToken string              `json:"captcha_token,omitempty"` // captcha 前置验证 token
}

// CreateResponse 创建 Challenge 响应
type CreateResponse struct {
	ChallengeID string         `json:"challenge_id"`
	Type        string         `json:"type"`
	ExpiresIn   int            `json:"expires_in"` // 秒
	Data        map[string]any `json:"data,omitempty"`
}

// CaptchaRequiredResponse 需要 Captcha 的响应
type CaptchaRequiredResponse struct {
	Error   string `json:"error"` // captcha_required
	SiteKey string `json:"site_key"`
}

// VerifyRequest 验证 Challenge 请求
type VerifyRequest struct {
	ChallengeID string `json:"challenge_id" binding:"required"`
	Code        string `json:"code,omitempty"`  // totp/email 验证码
	Token       string `json:"token,omitempty"` // captcha token
}

// VerifyResponse 验证 Challenge 响应
type VerifyResponse struct {
	Verified bool `json:"verified"`
}
