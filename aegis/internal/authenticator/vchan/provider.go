// Package vchan provides verification channel provider implementations.
package vchan

import (
	"context"

	"github.com/heliannuuthus/helios/aegis/internal/types"
)

// Provider 验证渠道提供者接口
// 与 factor.Provider 方法签名相同，但分属不同包、代表不同概念
// factor = 认证因子（email_otp / totp / webauthn）
// vchan  = 验证渠道（captcha 等前置验证）
type Provider interface {
	// Type 返回渠道类型标识
	Type() string

	// Initiate 启动验证渠道（如 captcha 无副作用，直接返回）
	// channel: 验证目标
	// params: clientID, audience, bizType（通过 ParseInitiateParams 解析）
	Initiate(ctx context.Context, channel string, params ...any) (*InitiateResult, error)

	// Verify 验证凭证
	// proof: 验证证明
	// params: 额外参数（如 remoteIP）
	Verify(ctx context.Context, proof string, params ...any) (bool, error)

	// Prepare 准备前端所需的公开配置
	Prepare() *types.ConnectionConfig
}

// InitiateResult Initiate 方法的返回结果
type InitiateResult struct {
	Challenge  *types.Challenge // 构建的 Challenge 对象
	RetryAfter int              // 下次可重发的冷却时间（秒）
}
