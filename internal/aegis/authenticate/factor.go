package authenticate

import (
	"context"

	"github.com/heliannuuthus/helios/internal/aegis/authenticator/factor"
	autherrors "github.com/heliannuuthus/helios/internal/aegis/errors"
	"github.com/heliannuuthus/helios/internal/aegis/types"
)

// FactorAuthenticator 认证因子认证器胶水层
// 一对一包装一个 factor.Provider，实现统一的 Authenticator 接口
type FactorAuthenticator struct {
	provider factor.Provider
}

// NewFactorAuthenticator 创建认证因子认证器
func NewFactorAuthenticator(provider factor.Provider) *FactorAuthenticator {
	return &FactorAuthenticator{
		provider: provider,
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

// Provider 返回底层 factor.Provider
func (a *FactorAuthenticator) Provider() factor.Provider {
	return a.provider
}

// Authenticate 执行认证因子验证
// params: [proof string, ...extraParams]
// 内部调用 provider.Verify()，成功后设置 Verified = true
func (a *FactorAuthenticator) Authenticate(ctx context.Context, flow *types.AuthFlow, params ...any) (bool, error) {
	// 从 params 提取 proof
	if len(params) < 1 {
		return false, autherrors.NewInvalidRequest("factor proof is required")
	}
	proof, ok := params[0].(string)
	if !ok {
		return false, autherrors.NewInvalidRequest("factor proof must be a string")
	}

	// 剩余 params 传给 provider
	extraParams := params[1:]

	// 调用 Provider.Verify
	success, err := a.provider.Verify(ctx, proof, extraParams...)
	if err != nil {
		return false, autherrors.NewServerErrorf("factor verification failed: %v", err)
	}
	if !success {
		return false, autherrors.NewInvalidCredentials("factor verification failed")
	}

	// 标记当前 connection 已验证
	if connCfg := flow.GetCurrentConnConfig(); connCfg != nil {
		connCfg.Verified = true
	}

	return true, nil
}
