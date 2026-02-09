package mfa

import (
	"context"
	"fmt"
	"net/http"

	"github.com/heliannuuthus/helios/internal/aegis/authenticator/webauthn"
	"github.com/heliannuuthus/helios/internal/aegis/types"
	"github.com/heliannuuthus/helios/pkg/logger"
)

// WebAuthnProvider WebAuthn MFA Provider
// 用于 MFA 验证场景（区别于 Passkey IDP 的无密码登录场景）
type WebAuthnProvider struct {
	webauthnSvc *webauthn.Service
}

// NewWebAuthnProvider 创建 WebAuthn MFA Provider
func NewWebAuthnProvider(webauthnSvc *webauthn.Service) *WebAuthnProvider {
	return &WebAuthnProvider{
		webauthnSvc: webauthnSvc,
	}
}

// Type 返回 MFA 类型标识
func (*WebAuthnProvider) Type() string {
	return TypeWebAuthn
}

// Verify 验证 WebAuthn 凭证
// proof: challengeID
// params[0]: *http.Request（用于解析 WebAuthn 响应）
func (p *WebAuthnProvider) Verify(ctx context.Context, proof string, params ...any) (bool, error) {
	if p.webauthnSvc == nil {
		return false, fmt.Errorf("webauthn service not configured")
	}

	challengeID := proof
	if challengeID == "" {
		return false, fmt.Errorf("challenge_id is required")
	}

	var r *http.Request
	if len(params) > 0 {
		if req, ok := params[0].(*http.Request); ok {
			r = req
		}
	}
	if r == nil {
		return false, fmt.Errorf("http request is required for webauthn verification")
	}

	// 完成 WebAuthn 验证
	_, credential, err := p.webauthnSvc.FinishLogin(ctx, challengeID, r)
	if err != nil {
		logger.Errorf("[WebAuthn MFA] FinishLogin failed: %v", err)
		return false, fmt.Errorf("webauthn verification failed: %w", err)
	}

	// 更新凭证签名计数
	if credential != nil {
		if err := p.webauthnSvc.UpdateCredentialSignCount(ctx, string(credential.ID), credential.Authenticator.SignCount); err != nil {
			logger.Warnf("[WebAuthn MFA] UpdateCredentialSignCount failed: %v", err)
		}
	}

	return true, nil
}

// Prepare 准备前端公开配置
func (p *WebAuthnProvider) Prepare() *types.ConnectionConfig {
	cfg := &types.ConnectionConfig{
		Connection: TypeWebAuthn,
	}
	if p.webauthnSvc != nil {
		cfg.Identifier = p.webauthnSvc.GetRPID()
	}
	return cfg
}
