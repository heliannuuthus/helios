package authenticate

import (
	"context"

	"github.com/heliannuuthus/helios/internal/aegis/authenticator/mfa"
	autherrors "github.com/heliannuuthus/helios/internal/aegis/errors"
	"github.com/heliannuuthus/helios/internal/aegis/types"
)

// MFAAuthenticator MFA 认证器胶水层
// 一对一包装一个 mfa.Provider，实现统一的 Authenticator 接口
type MFAAuthenticator struct {
	provider mfa.Provider
}

// NewMFAAuthenticator 创建 MFA 认证器
func NewMFAAuthenticator(provider mfa.Provider) *MFAAuthenticator {
	return &MFAAuthenticator{
		provider: provider,
	}
}

// Type 返回认证器类型标识
func (a *MFAAuthenticator) Type() string {
	return a.provider.Type()
}

// Prepare 返回前端公开配置
func (a *MFAAuthenticator) Prepare() *types.ConnectionConfig {
	return a.provider.Prepare()
}

// Provider 返回底层 mfa.Provider
func (a *MFAAuthenticator) Provider() mfa.Provider {
	return a.provider
}

// Authenticate 执行 MFA 验证
// params: [proof string, ...extraParams]
// 内部调用 provider.Verify()，成功后设置 Verified = true
func (a *MFAAuthenticator) Authenticate(ctx context.Context, flow *types.AuthFlow, params ...any) (bool, error) {
	// 从 params 提取 proof
	if len(params) < 1 {
		return false, autherrors.NewInvalidRequest("mfa proof is required")
	}
	proof, ok := params[0].(string)
	if !ok {
		return false, autherrors.NewInvalidRequest("mfa proof must be a string")
	}

	// 剩余 params 传给 provider
	extraParams := params[1:]

	// 调用 Provider.Verify
	success, err := a.provider.Verify(ctx, proof, extraParams...)
	if err != nil {
		return false, autherrors.NewServerErrorf("mfa verification failed: %v", err)
	}
	if !success {
		return false, autherrors.NewInvalidCredentials("mfa verification failed")
	}

	// 标记当前 connection 已验证
	if connCfg := flow.GetCurrentConnConfig(); connCfg != nil {
		connCfg.Verified = true
	}

	return true, nil
}
