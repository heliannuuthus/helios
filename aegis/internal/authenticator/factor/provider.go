// Package factor provides authentication factor provider implementations.
package factor

import (
	"context"
	"fmt"

	"github.com/heliannuuthus/helios/aegis/config"
	"github.com/heliannuuthus/helios/aegis/internal/types"
)

// 因子类型常量
const (
	TypeEmailOTP = "email_otp" // 邮件验证码
	TypeTOTP     = "totp"      // 时间动态口令
	TypeWebAuthn = "webauthn"  // WebAuthn/FIDO2
)

// Provider 认证因子提供者接口
type Provider interface {
	// Type 返回因子类型标识
	Type() string

	// Initiate 校验 channel 参数、执行副作用（发邮件等）、构建并返回 Challenge
	// channel: 验证目标（邮箱 / user_id / wx_code 等）
	// params: clientID, audience, bizType（通过 ParseInitiateParams 解析）
	Initiate(ctx context.Context, channel string, params ...any) (*InitiateResult, error)

	// Verify 验证认证因子凭证
	// proof: 验证凭证（OTP code / WebAuthn response 等）
	// params: 额外参数（如 challengeID、channel 等）
	Verify(ctx context.Context, proof string, params ...any) (bool, error)

	// Prepare 准备前端所需的公开配置
	Prepare() *types.ConnectionConfig
}

// InitiateResult Initiate 方法的返回结果
type InitiateResult struct {
	Challenge  *types.Challenge // 构建的 Challenge 对象
	RetryAfter int              // 下次可重发的冷却时间（秒）
}

// InitiateParams Initiate 方法的通用参数（通过 ...params 传入）
// params[0]: clientID (string)
// params[1]: audience (string)
// params[2]: bizType  (string) — 验证类的业务场景，交换类为空
type InitiateParams struct {
	ClientID string
	Audience string
	BizType  string
}

// ParseInitiateParams 从 ...params 中解析 Initiate 通用参数
func ParseInitiateParams(params ...any) (*InitiateParams, error) {
	if len(params) < 2 {
		return nil, fmt.Errorf("initiate requires at least clientID and audience")
	}
	clientID, ok := params[0].(string)
	if !ok || clientID == "" {
		return nil, fmt.Errorf("clientID is required")
	}
	audience, ok := params[1].(string)
	if !ok || audience == "" {
		return nil, fmt.Errorf("audience is required")
	}
	var bizType string
	if len(params) >= 3 {
		if t, ok := params[2].(string); ok {
			bizType = t
		}
	}
	return &InitiateParams{ClientID: clientID, Audience: audience, BizType: bizType}, nil
}

// NewChallenge 基于 Initiate 参数和 ChannelType 构建 Challenge 对象
// 注意：此函数仅用于 Provider 内部生成临时 Challenge（用于 ID 生成等）
// 实际使用时 Limits 和 IP 由外层 InitiateRequest.NewChallenge 填充
func NewChallenge(channelType types.ChannelType, channel string, p *InitiateParams) *types.Challenge {
	return types.NewChallenge(p.ClientID, p.Audience, p.BizType, channelType, channel, config.GetChallengeBusinessExpiresIn(), nil, "")
}
