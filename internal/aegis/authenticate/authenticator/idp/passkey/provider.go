// Package passkey provides Passkey (WebAuthn) passwordless login as an IDP.
package passkey

import (
	"context"
	"fmt"
	"net/http"

	"github.com/heliannuuthus/helios/internal/aegis/authenticate/authenticator/idp"
	"github.com/heliannuuthus/helios/internal/aegis/authenticate/authenticator/webauthn"
	"github.com/heliannuuthus/helios/internal/aegis/types"
	"github.com/heliannuuthus/helios/pkg/logger"
)

const (
	// TypePasskey Passkey IDP 类型标识
	TypePasskey = "passkey"
)

// Provider Passkey 身份提供者
// 用于无密码登录场景（Discoverable Credentials）
type Provider struct {
	webauthnSvc *webauthn.Service
}

// NewProvider 创建 Passkey Provider
func NewProvider(webauthnSvc *webauthn.Service) *Provider {
	return &Provider{
		webauthnSvc: webauthnSvc,
	}
}

// Type 返回 IDP 类型
func (*Provider) Type() string {
	return TypePasskey
}

// Login 执行 Passkey 登录
// proof: challengeID（前端完成 WebAuthn 认证后返回的 challenge ID）
// params[0]: *http.Request（用于解析 WebAuthn 响应）
func (p *Provider) Login(ctx context.Context, proof string, params ...any) (*idp.LoginResult, error) {
	if p.webauthnSvc == nil {
		return nil, fmt.Errorf("webauthn service not configured")
	}

	challengeID := proof
	if challengeID == "" {
		return nil, fmt.Errorf("challenge_id is required")
	}

	// 从 params 中获取 http.Request
	var r *http.Request
	if len(params) > 0 {
		if req, ok := params[0].(*http.Request); ok {
			r = req
		}
	}
	if r == nil {
		return nil, fmt.Errorf("http request is required for passkey login")
	}

	// 完成 WebAuthn 登录验证
	userID, credential, err := p.webauthnSvc.FinishLogin(ctx, challengeID, r)
	if err != nil {
		logger.Errorf("[Passkey] FinishLogin failed: %v", err)
		return nil, fmt.Errorf("passkey authentication failed: %w", err)
	}

	// 更新凭证签名计数（防重放）
	if credential != nil {
		if err := p.webauthnSvc.UpdateCredentialSignCount(ctx, string(credential.ID), credential.Authenticator.SignCount); err != nil {
			logger.Warnf("[Passkey] UpdateCredentialSignCount failed: %v", err)
		}
	}

	logger.Infof("[Passkey] Login success - UserID: %s", userID)

	return &idp.LoginResult{
		ProviderID: userID,
		RawData:    fmt.Sprintf(`{"user_id":"%s","challenge_id":"%s"}`, userID, challengeID),
	}, nil
}

// FetchAdditionalInfo Passkey 不支持获取额外信息
func (*Provider) FetchAdditionalInfo(_ context.Context, _ string, _ ...any) (*idp.AdditionalInfo, error) {
	return nil, fmt.Errorf("passkey does not support fetching additional info")
}

// Prepare 准备前端配置
func (p *Provider) Prepare() *types.ConnectionConfig {
	cfg := &types.ConnectionConfig{
		Connection: TypePasskey,
	}

	// 添加 RP ID 作为 identifier
	if p.webauthnSvc != nil {
		cfg.Identifier = p.webauthnSvc.GetRPID()
	}

	return cfg
}

// BeginLogin 开始 Passkey 登录流程
// 返回 WebAuthn options 供前端使用
func (p *Provider) BeginLogin(ctx context.Context) (*webauthn.LoginBeginResponse, error) {
	if p.webauthnSvc == nil {
		return nil, fmt.Errorf("webauthn service not configured")
	}

	// 使用 Discoverable Login（无需提前知道用户）
	return p.webauthnSvc.BeginDiscoverableLogin(ctx)
}
