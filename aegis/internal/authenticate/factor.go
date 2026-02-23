package authenticate

import (
	"context"

	"github.com/heliannuuthus/helios/aegis/config"
	autherrors "github.com/heliannuuthus/helios/aegis/errors"
	"github.com/heliannuuthus/helios/aegis/internal/authenticator"
	"github.com/heliannuuthus/helios/aegis/internal/authenticator/factor"
	"github.com/heliannuuthus/helios/aegis/internal/types"
	"github.com/heliannuuthus/helios/pkg/accessctl"
)

var (
	_ authenticator.Authenticator     = (*FactorAuthenticator)(nil)
	_ authenticator.ChallengeVerifier = (*FactorAuthenticator)(nil)
)

// FactorAuthenticator 认证因子认证器包装器
// 持有 factor.Provider，同时实现 Authenticator + ChallengeVerifier
type FactorAuthenticator struct {
	provider factor.Provider
	ac       *accessctl.Manager
}

// NewFactorAuthenticator 创建认证因子认证器
func NewFactorAuthenticator(provider factor.Provider, ac *accessctl.Manager) *FactorAuthenticator {
	return &FactorAuthenticator{
		provider: provider,
		ac:       ac,
	}
}

// Type 返回认证器类型标识
func (a *FactorAuthenticator) Type() string {
	return a.provider.Type()
}

// ConnectionType 返回连接类型
func (a *FactorAuthenticator) ConnectionType() types.ConnectionType {
	return types.ConnTypeFactor
}

// Prepare 返回完整配置（含 Type）
func (a *FactorAuthenticator) Prepare() *types.ConnectionConfig {
	cfg := a.provider.Prepare()
	if cfg != nil {
		cfg.Type = types.ConnTypeFactor
	}
	return cfg
}

// Authenticate 执行认证因子验证（Login 流程）
// params: [proof string, ...extraParams]
func (a *FactorAuthenticator) Authenticate(ctx context.Context, flow *types.AuthFlow, params ...any) (bool, error) {
	if len(params) < 1 {
		return false, autherrors.NewInvalidRequest("factor proof is required")
	}
	proof, ok := params[0].(string)
	if !ok {
		return false, autherrors.NewInvalidRequest("factor proof must be a string")
	}

	extraParams := params[1:]

	success, err := a.provider.Verify(ctx, proof, extraParams...)
	if err != nil {
		return false, autherrors.NewServerErrorf("factor verification failed: %v", err)
	}
	if !success {
		return false, autherrors.NewInvalidCredentials("factor verification failed")
	}

	if connCfg := flow.GetCurrentConnConfig(); connCfg != nil {
		connCfg.Verified = true
	}

	return true, nil
}

// ==================== ChallengeVerifier 实现 ====================

// Initiate 启动 Challenge（限流检查 + 委托 factor.Provider.Initiate）
func (a *FactorAuthenticator) Initiate(ctx context.Context, challenge *types.Challenge) (int, error) {
	// 1. 限流检查
	retryAfter, err := a.probeRate(ctx, challenge)
	if err != nil {
		return 0, err
	}

	// 2. 委托 Provider 执行副作用
	result, err := a.provider.Initiate(ctx, challenge.Channel, challenge.ClientID, challenge.Audience, challenge.Type)
	if err != nil {
		return 0, err
	}

	// 将 Provider 产生的 Challenge 数据同步回原 Challenge（保持原 ID）
	if result.Challenge != nil && result.Challenge.Data != nil {
		for k, v := range result.Challenge.Data {
			challenge.SetData(k, v)
		}
	}

	// 优先使用 Provider 返回的 retryAfter（如果有）
	if result.RetryAfter > 0 {
		retryAfter = result.RetryAfter
	}

	return retryAfter, nil
}

// probeRate 检查限流（IP + Channel 维度），返回 retryAfter 或 error
func (a *FactorAuthenticator) probeRate(ctx context.Context, challenge *types.Challenge) (retryAfter int, err error) {
	// 1. IP 维度限流
	if ip := challenge.IP; ip != "" {
		ipKey := types.RateLimitKeyPrefixCreateIP + ip
		ipPolicy := accessctl.NewPolicy(ipKey).RateLimits(config.GetRateLimitIPLimits())
		if waitSeconds := a.ac.ProbeRate(ctx, ipPolicy); waitSeconds > 0 {
			return 0, autherrors.NewTooManyRequests(waitSeconds)
		}
	}

	// 2. Channel 维度限流（从 challenge.Limits 读取）
	if len(challenge.Limits) > 0 {
		channelKey := types.RateLimitKeyPrefixCreate + challenge.Audience + ":" + challenge.Type + ":" + challenge.Channel
		policy := accessctl.NewPolicy(channelKey).RateLimits(challenge.Limits)
		if waitSeconds := a.ac.ProbeRate(ctx, policy); waitSeconds > 0 {
			return 0, autherrors.NewTooManyRequests(waitSeconds)
		}
	}

	// 3. 没被限流，返回最小窗口作为前端倒计时
	return config.GetRetryAfterFromLimits(challenge.Limits), nil
}

// Verify 验证 Challenge proof（委托 factor.Provider.Verify）
func (a *FactorAuthenticator) Verify(ctx context.Context, challenge *types.Challenge, proof string) (bool, error) {
	return a.provider.Verify(ctx, proof, challenge.Channel, challenge.ID)
}
