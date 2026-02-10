package mfa

import (
	"context"
	"fmt"

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
// proof: WebAuthn assertion JSON（前端 navigator.credentials.get() 序列化结果）
// params[0]: challengeID (string)
func (p *WebAuthnProvider) Verify(ctx context.Context, proof string, params ...any) (bool, error) {
	if p.webauthnSvc == nil {
		return false, fmt.Errorf("webauthn service not configured")
	}

	if proof == "" {
		return false, fmt.Errorf("webauthn assertion is required")
	}

	// 从 params 获取 challengeID
	var challengeID string
	if len(params) > 0 {
		if id, ok := params[0].(string); ok {
			challengeID = id
		}
	}
	if challengeID == "" {
		return false, fmt.Errorf("challenge_id is required")
	}

	// 完成 WebAuthn 验证（从 proof 解析 assertion，不依赖 *http.Request）
	_, credential, err := p.webauthnSvc.FinishLogin(ctx, challengeID, []byte(proof))
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
