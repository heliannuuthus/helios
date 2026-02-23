// Package passkey provides Passkey (WebAuthn) passwordless login as an IDP.
package passkey

import (
	"context"
	"fmt"

	"github.com/heliannuuthus/helios/aegis/internal/authenticator/webauthn"
	"github.com/heliannuuthus/helios/aegis/internal/authenticator/idp"
	"github.com/heliannuuthus/helios/aegis/internal/types"
	"github.com/heliannuuthus/helios/hermes/models"
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
// proof: WebAuthn assertion JSON（前端 navigator.credentials.get() 序列化结果，包含 challengeID）
// params[0]: principal（忽略）
// params[1]: strategy（忽略）
func (p *Provider) Login(ctx context.Context, proof string, params ...any) (*models.TUserInfo, error) {
	if p.webauthnSvc == nil {
		return nil, fmt.Errorf("webauthn service not configured")
	}

	if proof == "" {
		return nil, fmt.Errorf("webauthn assertion is required")
	}

	// proof 即 assertion JSON，从中提取 challengeID
	// TODO: challengeID 应从 assertion 或 params 中获取，当前暂用 principal 传递
	var challengeID string
	if len(params) > 0 {
		if id, ok := params[0].(string); ok && id != "" {
			challengeID = id
		}
	}
	if challengeID == "" {
		return nil, fmt.Errorf("challenge_id is required (pass via principal)")
	}

	// 完成 WebAuthn 登录验证（从 proof 解析 assertion，不依赖 *http.Request）
	userID, credential, err := p.webauthnSvc.FinishLogin(ctx, challengeID, []byte(proof))
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

	return &models.TUserInfo{
		TOpenID: userID,
		RawData: fmt.Sprintf(`{"user_id":"%s","challenge_id":"%s"}`, userID, challengeID),
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
