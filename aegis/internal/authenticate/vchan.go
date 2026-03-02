package authenticate

import (
	"context"

	autherrors "github.com/heliannuuthus/helios/aegis/errors"
	"github.com/heliannuuthus/helios/aegis/internal/authenticator"
	"github.com/heliannuuthus/helios/aegis/internal/authenticator/vchan"
	"github.com/heliannuuthus/helios/aegis/internal/types"
	"github.com/heliannuuthus/helios/pkg/helpers"
)

// 编译期接口检查
var (
	_ authenticator.Authenticator     = (*VChanAuthenticator)(nil)
	_ authenticator.ChallengeVerifier = (*VChanAuthenticator)(nil)
)

// VChanAuthenticator 验证渠道认证器包装器
// 持有 vchan.Provider，同时实现 Authenticator + ChallengeVerifier
type VChanAuthenticator struct {
	provider vchan.Provider
}

// NewVChanAuthenticator 创建验证渠道认证器
func NewVChanAuthenticator(provider vchan.Provider) *VChanAuthenticator {
	return &VChanAuthenticator{
		provider: provider,
	}
}

// Type 返回认证器类型标识
func (a *VChanAuthenticator) Type() string {
	return a.provider.Type()
}

// ConnectionType 返回连接类型
func (a *VChanAuthenticator) ConnectionType() types.ConnectionType {
	return types.ConnTypeVChan
}

// Prepare 返回完整配置（含 Type）
func (a *VChanAuthenticator) Prepare() *types.ConnectionConfig {
	cfg := a.provider.Prepare()
	if cfg != nil {
		cfg.Type = types.ConnTypeVChan
	}
	return cfg
}

// Authenticate 执行验证渠道认证（Login 流程）
// params 约定顺序：[0]proof, [1]principal, [2]strategy
// remoteIP 通过 context 传递
func (a *VChanAuthenticator) Authenticate(ctx context.Context, flow *types.AuthFlow, params ...any) (bool, error) {
	if len(params) < 1 {
		return false, autherrors.NewInvalidRequest("vchan proof is required")
	}
	proof, ok := params[0].(string)
	if !ok {
		return false, autherrors.NewInvalidRequest("vchan proof must be a string")
	}

	// 从 params[2] 获取 strategy
	var strategy string
	if len(params) >= 3 {
		if s, ok := params[2].(string); ok {
			strategy = s
		}
	}

	success, err := a.provider.Verify(ctx, proof, strategy, helpers.RemoteIPFrom(ctx))
	if err != nil {
		return false, autherrors.NewServerErrorf("vchan verification failed: %v", err)
	}
	if !success {
		return false, autherrors.NewInvalidRequest("vchan verification failed")
	}

	if connCfg := flow.GetCurrentConnConfig(); connCfg != nil {
		connCfg.Verified = true
	}

	return true, nil
}

// ==================== ChallengeVerifier 实现 ====================

func (a *VChanAuthenticator) Initiate(ctx context.Context, challenge *types.Challenge) error {
	return a.provider.Initiate(ctx, challenge)
}

// Verify 验证 Challenge proof（委托 vchan.Provider.Verify）
// strategy 从 challenge.Data["strategy"] 读取
// remoteIP 通过 context 传递
func (a *VChanAuthenticator) Verify(ctx context.Context, challenge *types.Challenge, proof string) (bool, error) {
	strategy := challenge.GetStringData("strategy")
	return a.provider.Verify(ctx, proof, strategy, helpers.RemoteIPFrom(ctx))
}
