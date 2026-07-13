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

// Login 执行 Passkey 登录。
// proof: WebAuthn assertion JSON
// params[0]: appID（由 IDPAuthenticator 注入，Passkey 不使用）
// params[1]: principal（忽略）
// params[2]: strategy（忽略）
// params[3]: uid（由 Initiate 返回的 ceremony uid）
func (p *Provider) Login(ctx context.Context, proof string, params ...any) (*models.TUserInfo, error) {
	uid := stringParam(params, 3)
	if uid == "" {
		return nil, fmt.Errorf("uid is required")
	}
	return p.verify(ctx, uid, proof)
}

// Initiate 初始化 Passkey discoverable ceremony。
func (p *Provider) Initiate(ctx context.Context, _ *idp.InitiateContext, _ string) (*idp.InitiateResponse, error) {
	options, err := p.InitializeLogin(ctx)
	if err != nil {
		return nil, err
	}
	return &idp.InitiateResponse{
		UID:     options.CeremonyID,
		Options: options.Options,
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

func (p *Provider) verify(ctx context.Context, uid, proof string) (*models.TUserInfo, error) {
	if uid == "" {
		return nil, fmt.Errorf("uid is required")
	}
	if proof == "" {
		return nil, fmt.Errorf("webauthn assertion is required")
	}

	userID, credential, err := p.webauthnSvc.VerifyAuthentication(ctx, uid, []byte(proof))
	if err != nil {
		logger.Errorf("[Passkey] VerifyAuthentication failed: %v", err)
		return nil, fmt.Errorf("passkey authentication failed: %w", err)
	}

	if credential != nil {
		credentialID := base64.RawURLEncoding.EncodeToString(credential.ID)
		if err := p.webauthnSvc.PatchCredentialSignCount(ctx, credentialID, credential.Authenticator.SignCount); err != nil {
			logger.Warnf("[Passkey] PatchCredentialSignCount failed: %v", err)
		}
	}

	return &models.TUserInfo{
		TOpenID: userID,
		RawData: fmt.Sprintf(`{"user_id":"%s","type":"passkey","uid":"%s"}`, userID, uid),
	}, nil
}

func stringParam(params []any, index int) string {
	if len(params) <= index {
		return ""
	}
	value, ok := params[index].(string)
	if !ok {
		return ""
	}
	return value
}
