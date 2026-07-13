// Package passkey provides Passkey (WebAuthn) passwordless login as an IDP.
package passkey

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/heliannuuthus/aegis/internal/authenticator/idp"
	"github.com/heliannuuthus/aegis/internal/authenticator/webauthn"
	"github.com/heliannuuthus/aegis/internal/types"
	"github.com/heliannuuthus/aegis/models"
	"github.com/heliannuuthus/pkg/logger"
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
	userID, credential, err := p.webauthnSvc.VerifyAuthentication(ctx, challengeID, []byte(proof))
	if err != nil {
		logger.Errorf("[Passkey] VerifyAuthentication failed: %v", err)
		return nil, fmt.Errorf("passkey authentication failed: %w", err)
	}

	// 更新凭证签名计数（防重放）
	if credential != nil {
		credentialID := base64.RawURLEncoding.EncodeToString(credential.ID)
		if err := p.webauthnSvc.PatchCredentialSignCount(ctx, credentialID, credential.Authenticator.SignCount); err != nil {
			logger.Warnf("[Passkey] PatchCredentialSignCount failed: %v", err)
		}
	}

	logger.Infof("[Passkey] Login success - UserID: %s", userID)

	return &models.TUserInfo{
		TOpenID: userID,
		RawData: fmt.Sprintf(`{"user_id":"%s","challenge_id":"%s"}`, userID, challengeID),
	}, nil
}

// Resolve Passkey 不支持通过 principal 本地查找
func (*Provider) Resolve(_ context.Context, _ string) (*models.TUserInfo, error) {
	return nil, fmt.Errorf("passkey provider does not support resolve")
}

// FetchAdditionalInfo Passkey 不支持获取额外信息
func (*Provider) FetchAdditionalInfo(_ context.Context, _ string, _ ...any) (*idp.AdditionalInfo, error) {
	return nil, fmt.Errorf("passkey does not support fetching additional info")
}

// Prepare 准备前端配置
func (p *Provider) Prepare() *types.ConnectionConfig {
	return &types.ConnectionConfig{
		Connection: TypePasskey,
		Identifier: p.webauthnSvc.GetRPID(),
	}
}

// InitializeLogin 初始化 Passkey 登录流程
// 返回 WebAuthn options 供前端使用
func (p *Provider) InitializeLogin(ctx context.Context) (*webauthn.AuthenticationOptions, error) {
	ceremonyID := types.GenerateChallengeID()
	options, err := p.webauthnSvc.InitializeDiscoverableAuthenticationCeremony(ctx, ceremonyID, webauthn.DefaultWebAuthnCeremonyTTL)
	if err != nil {
		return nil, err
	}
	return &webauthn.AuthenticationOptions{
		Options:    options,
		CeremonyID: ceremonyID,
	}, nil
}
