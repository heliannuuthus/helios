// Package challenge provides challenge verification service.
package challenge

import (
	"math"
	"time"

	"github.com/heliannuuthus/helios/aegis/internal/types"
	"github.com/heliannuuthus/helios/hermes/models"
)

// ChallengeRequired 是 types.ChallengeRequired 的别名
type ChallengeRequired = types.ChallengeRequired

// ==================== Initiate ====================

// InitiateRequest 创建 Challenge 请求（三层模型：type / channel_type / channel）
type InitiateRequest struct {
	ClientID    string `json:"client_id" binding:"required"`    // 应用 ID
	Audience    string `json:"audience" binding:"required"`     // 目标服务 ID
	Type        string `json:"type,omitempty"`                  // 业务场景（验证类必填，交换类忽略）
	ChannelType string `json:"channel_type" binding:"required"` // 验证方式
	Channel     string `json:"channel" binding:"required"`      // 验证目标（邮箱 / 手机号 / user_id / wx_code ...）
}

// NewChallenge 根据 ServiceChallengeSetting 创建 Challenge 对象
func (r *InitiateRequest) NewChallenge(setting *models.ServiceChallengeSetting, ip string) *types.Challenge {
	var expiresIn time.Duration
	if setting.ExpiresIn > math.MaxInt64/uint(time.Second) {
		expiresIn = time.Duration(math.MaxInt64)
	} else {
		expiresIn = time.Duration(setting.ExpiresIn) * time.Second
	}
	return types.NewChallenge(
		r.ClientID, r.Audience, r.Type,
		types.ChannelType(r.ChannelType), r.Channel,
		expiresIn, setting.Limits, ip,
	)
}

// InitiateResponse 创建 Challenge 响应
type InitiateResponse struct {
	ChallengeID string            `json:"challenge_id"`
	RetryAfter  int               `json:"retry_after,omitempty"` // 下次可重发的等待秒数
	Required    ChallengeRequired `json:"required,omitempty"`    // 前置条件
}

// ==================== Verify ====================

// VerifyRequest 验证 Challenge 请求（challenge_id 从 path 获取）
type VerifyRequest struct {
	Type     string `json:"type" binding:"required"`  // 当前提交的是哪个前置条件（对应 Required 中的 key，如 "captcha"）
	Strategy string `json:"strategy,omitempty"`       // 验证方式（如 "turnstile"），前置条件验证时必填
	Proof    any    `json:"proof" binding:"required"` // 验证证明
}

// VerifyResponse handler 层返回给前端的 HTTP 响应
type VerifyResponse struct {
	Verified       bool              `json:"verified"`
	ChallengeToken string            `json:"challenge_token,omitempty"` // 验证成功后的凭证（handler 签发）
	Required       ChallengeRequired `json:"required,omitempty"`        // 前置未完成时引导渲染
	RetryAfter     int               `json:"retry_after,omitempty"`     // 下次可重发的等待秒数
	ExpiresIn      int               `json:"expires_in,omitempty"`      // token 有效期（秒）
}

// ==================== Exchange ====================

// ExchangeRequest 交换类 Challenge 请求（一步完成，不需要 Initiate/Verify 两步流程）
type ExchangeRequest struct {
	ClientID    string `json:"client_id" binding:"required"`    // 应用 ID
	Audience    string `json:"audience" binding:"required"`     // 目标服务 ID
	ChannelType string `json:"channel_type" binding:"required"` // 交换方式（wechat-mp / alipay-mp）
	Code        string `json:"code" binding:"required"`         // 平台授权码
}

// ExchangeResponse 交换类 Challenge 响应
type ExchangeResponse struct {
	ChallengeToken string `json:"challenge_token"` // 验证成功后的凭证
}
