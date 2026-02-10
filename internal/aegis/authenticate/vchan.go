package authenticate

import (
	"context"

	"github.com/heliannuuthus/helios/internal/aegis/authenticator/captcha"
	autherrors "github.com/heliannuuthus/helios/internal/aegis/errors"
	"github.com/heliannuuthus/helios/internal/aegis/types"
)

// VChanAuthenticator 验证渠道认证器胶水层
// 包装 captcha.Verifier，实现统一的 Authenticator 接口
type VChanAuthenticator struct {
	verifier   captcha.Verifier
	connection string // "captcha"
}

// NewVChanAuthenticator 创建验证渠道认证器
func NewVChanAuthenticator(verifier captcha.Verifier) *VChanAuthenticator {
	return &VChanAuthenticator{
		verifier:   verifier,
		connection: "captcha",
	}
}

// Type 返回认证器类型标识
func (a *VChanAuthenticator) Type() string {
	return a.connection
}

// Prepare 返回前端公开配置
func (a *VChanAuthenticator) Prepare() *types.ConnectionConfig {
	return &types.ConnectionConfig{
		Connection: a.connection,
		Identifier: a.verifier.GetIdentifier(),
		Strategy:   []string{a.verifier.GetProvider()}, // e.g. ["turnstile"]
	}
}

// Authenticate 执行人机验证
// params 约定顺序（与 handler.Login 解包一致）：[0]proof, [1]principal, [2]strategy, [3]remoteIP
func (a *VChanAuthenticator) Authenticate(ctx context.Context, flow *types.AuthFlow, params ...any) (bool, error) {
	// 从 params[0] 提取 proof（captcha token）
	if len(params) < 1 {
		return false, autherrors.NewInvalidRequest("captcha proof is required")
	}
	proof, ok := params[0].(string)
	if !ok {
		return false, autherrors.NewInvalidRequest("captcha proof must be a string")
	}

	// 从 params[3] 提取 remoteIP（可选）
	var remoteIP string
	if len(params) >= 4 {
		if ip, ok := params[3].(string); ok {
			remoteIP = ip
		}
	}

	// 调用 Verifier.Verify
	success, err := a.verifier.Verify(ctx, proof, remoteIP)
	if err != nil {
		return false, autherrors.NewServerErrorf("captcha verification failed: %v", err)
	}
	if !success {
		return false, autherrors.NewInvalidRequest("captcha verification failed")
	}

	// 标记当前 connection 已验证
	if connCfg := flow.GetCurrentConnConfig(); connCfg != nil {
		connCfg.Verified = true
	}

	return true, nil
}
