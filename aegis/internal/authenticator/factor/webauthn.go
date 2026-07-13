package factor

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/mail"

	"github.com/heliannuuthus/aegis/internal/authenticator/webauthn"
	"github.com/heliannuuthus/aegis/internal/types"
	"github.com/heliannuuthus/aegis/models"
	"github.com/heliannuuthus/aegis/rpc/hermes"
	"github.com/heliannuuthus/pkg/logger"
)

// WebAuthnProvider WebAuthn 认证因子 Provider
// 用于验证场景（区别于 Passkey IDP 的无密码登录场景）
type WebAuthnProvider struct {
	webauthnSvc *webauthn.Service
	users       *hermes.Client
}

// NewWebAuthnProvider 创建 WebAuthn 认证因子 Provider
func NewWebAuthnProvider(webauthnSvc *webauthn.Service, users *hermes.Client) *WebAuthnProvider {
	return &WebAuthnProvider{
		webauthnSvc: webauthnSvc,
		users:       users,
	}
}

// Type 返回因子类型标识
func (*WebAuthnProvider) Type() string {
	return TypeWebAuthn
}

func (p *WebAuthnProvider) Initiate(ctx context.Context, challenge *types.Challenge) error {
	if challenge == nil {
		return fmt.Errorf("challenge is required")
	}

	if challenge.Channel == "" {
		return fmt.Errorf("channel is required for webauthn factor")
	}

	user, err := p.resolveUser(ctx, challenge.Channel)
	if err != nil {
		return fmt.Errorf("resolve webauthn user: %w", err)
	}

	existingCredentials, err := p.webauthnSvc.ListCredentials(ctx, user.OpenID)
	if err != nil {
		return fmt.Errorf("list webauthn credentials: %w", err)
	}

	options, err := p.webauthnSvc.InitializeAuthenticationCeremony(ctx, challenge.ID, user, existingCredentials, challenge.ExpiresIn())
	if err != nil {
		return err
	}
	challenge.SetData(types.ChallengeDataOptions, options)
	return nil
}

// Verify 验证 WebAuthn 凭证
// proof: WebAuthn assertion JSON（前端 navigator.credentials.get() 序列化结果）
func (p *WebAuthnProvider) Verify(ctx context.Context, challenge *types.Challenge, proof string) (bool, error) {
	if proof == "" {
		return false, fmt.Errorf("webauthn assertion is required")
	}

	if challenge == nil || challenge.ID == "" {
		return false, fmt.Errorf("challenge_id is required")
	}

	// 完成 WebAuthn 验证（从 proof 解析 assertion，不依赖 *http.Request）
	_, credential, err := p.webauthnSvc.VerifyAuthentication(ctx, challenge.ID, []byte(proof))
	if err != nil {
		logger.Errorf("[WebAuthn Factor] VerifyAuthentication failed: %v", err)
		return false, fmt.Errorf("webauthn verification failed: %w", err)
	}

	// 更新凭证签名计数
	if credential != nil {
		credentialID := base64.RawURLEncoding.EncodeToString(credential.ID)
		if err := p.webauthnSvc.PatchCredentialSignCount(ctx, credentialID, credential.Authenticator.SignCount); err != nil {
			logger.Warnf("[WebAuthn Factor] PatchCredentialSignCount failed: %v", err)
		}
	}

	return true, nil
}

// Prepare 准备前端公开配置
func (p *WebAuthnProvider) Prepare() *types.ConnectionConfig {
	return &types.ConnectionConfig{
		Connection: TypeWebAuthn,
		Identifier: p.webauthnSvc.GetRPID(),
	}
}

func (p *WebAuthnProvider) resolveUser(ctx context.Context, principal string) (*models.UserWithDecrypted, error) {
	if p.users == nil {
		return nil, fmt.Errorf("user provider is not configured")
	}

	if user, err := p.users.GetUserByOpenID(ctx, principal); err == nil {
		return user, nil
	}

	if _, err := mail.ParseAddress(principal); err == nil {
		return p.users.GetUserByEmail(ctx, principal)
	}

	return p.users.GetUserByPhone(ctx, principal)
}
