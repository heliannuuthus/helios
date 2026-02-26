package authenticate

import (
	"context"
	"strings"

	"github.com/heliannuuthus/helios/aegis/config"
	autherrors "github.com/heliannuuthus/helios/aegis/errors"
	"github.com/heliannuuthus/helios/aegis/internal/authenticator"
	"github.com/heliannuuthus/helios/aegis/internal/authenticator/factor"
	"github.com/heliannuuthus/helios/aegis/internal/types"
	"github.com/heliannuuthus/helios/pkg/accessctl"
	tokendef "github.com/heliannuuthus/helios/pkg/aegis/utils/token"
	"github.com/heliannuuthus/helios/pkg/logger"
)

// ChallengeTokenVerifier challenge-token 验证能力接口
type ChallengeTokenVerifier interface {
	Verify(ctx context.Context, tokenString string) (tokendef.Token, error)
}

var (
	_ authenticator.Authenticator     = (*FactorAuthenticator)(nil)
	_ authenticator.ChallengeVerifier = (*FactorAuthenticator)(nil)
)

// FactorAuthenticator 认证因子认证器包装器
// 持有 factor.Provider，同时实现 Authenticator + ChallengeVerifier
//
// Login 阶段（Authenticate）：统一验证 challenge-token，不走 provider.Verify。
// Challenge 阶段（Initiate / Verify）：委托 provider 处理。
type FactorAuthenticator struct {
	provider      factor.Provider
	ac            *accessctl.Manager
	tokenVerifier ChallengeTokenVerifier
}

// NewFactorAuthenticator 创建认证因子认证器
func NewFactorAuthenticator(provider factor.Provider, ac *accessctl.Manager, tokenVerifier ChallengeTokenVerifier) *FactorAuthenticator {
	return &FactorAuthenticator{
		provider:      provider,
		ac:            ac,
		tokenVerifier: tokenVerifier,
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

// Authenticate 验证 challenge-token（Login 流程）
// Login 阶段提交 factor connection 时，proof 只能是 challenge-token。
// 校验规则：
//  1. token 签名和有效期有效
//  2. token 类型为 ChallengeToken
//  3. token.typ 以 "{delegatingIDP}:" 为前缀（如 staff:verify），确保 challenge 与主身份绑定
func (a *FactorAuthenticator) Authenticate(ctx context.Context, flow *types.AuthFlow, params ...any) (bool, error) {
	if len(params) < 1 {
		return false, autherrors.NewInvalidRequest("challenge token is required")
	}
	proof, ok := params[0].(string)
	if !ok || proof == "" {
		return false, autherrors.NewInvalidRequest("challenge token must be a non-empty string")
	}

	t, err := a.tokenVerifier.Verify(ctx, proof)
	if err != nil {
		return false, autherrors.NewInvalidCredentials("invalid challenge token")
	}

	ct, ok := t.(*tokendef.ChallengeToken)
	if !ok {
		return false, autherrors.NewInvalidCredentials("proof is not a challenge token")
	}

	delegatingIDP := findDelegatingIDP(flow, a.Type())
	if delegatingIDP == "" {
		return false, autherrors.NewInvalidRequest("factor is not a delegate of any IDP")
	}

	expectedPrefix := delegatingIDP + ":"
	if !strings.HasPrefix(ct.GetType(), expectedPrefix) {
		return false, autherrors.NewInvalidRequestf("challenge token type %q is not valid for IDP %q", ct.GetType(), delegatingIDP)
	}

	if connCfg := flow.GetCurrentConnConfig(); connCfg != nil {
		connCfg.Verified = true
	}

	logger.Infof("[Factor] challenge-token 验证通过 - Factor: %s, IDP: %s, Type: %s", a.Type(), delegatingIDP, ct.GetType())
	return true, nil
}

// findDelegatingIDP 查找 ConnectionMap 中哪个 IDP 的 Delegate 列表包含指定 connection
func findDelegatingIDP(flow *types.AuthFlow, connection string) string {
	for name, cfg := range flow.ConnectionMap {
		if cfg.Type != types.ConnTypeIDP {
			continue
		}
		for _, d := range cfg.Delegate {
			if d == connection {
				return name
			}
		}
	}
	return ""
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
