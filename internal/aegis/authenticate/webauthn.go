package authenticate

import (
	"context"
	"fmt"

	"github.com/heliannuuthus/helios/internal/aegis/cache"
	waservice "github.com/heliannuuthus/helios/internal/aegis/webauthn"
	"github.com/heliannuuthus/helios/pkg/logger"
)

// AuthTypeWebAuthn WebAuthn 认证类型
const AuthTypeWebAuthn AuthType = "webauthn"

// WebAuthnAuthenticator WebAuthn 认证器
// 用于 MFA 场景下的 WebAuthn 验证
type WebAuthnAuthenticator struct {
	cache     *cache.Manager
	webauthn  *waservice.Service
}

// NewWebAuthnAuthenticator 创建 WebAuthn 认证器
func NewWebAuthnAuthenticator(cm *cache.Manager, wa *waservice.Service) *WebAuthnAuthenticator {
	return &WebAuthnAuthenticator{
		cache:    cm,
		webauthn: wa,
	}
}

// Type 返回认证器类型
func (*WebAuthnAuthenticator) Type() AuthType {
	return AuthTypeWebAuthn
}

// Supports 判断是否支持该 connection
func (*WebAuthnAuthenticator) Supports(connection string) bool {
	return connection == "webauthn" || connection == "passkey"
}

// Authenticate 执行认证
// 对于 WebAuthn，认证流程分为两步：
// 1. BeginLogin - 生成 challenge（由 Handler 调用 WebAuthn Service）
// 2. FinishLogin - 验证响应（由 Handler 调用 WebAuthn Service）
//
// 这里处理的是 MFA 场景下的简化验证：
// data 中应包含已完成的 challenge_id
func (a *WebAuthnAuthenticator) Authenticate(ctx context.Context, _ string, data map[string]any) (*AuthResult, error) {
	// 获取 challenge_id
	challengeID, ok := data["challenge_id"].(string)
	if !ok || challengeID == "" {
		return nil, fmt.Errorf("challenge_id is required for webauthn authentication")
	}

	// 获取 Challenge
	challenge, err := a.cache.GetChallenge(ctx, challengeID)
	if err != nil {
		return nil, fmt.Errorf("challenge not found: %w", err)
	}

	// 检查 Challenge 是否已验证
	if !challenge.Verified {
		return nil, fmt.Errorf("webauthn challenge not verified")
	}

	// 检查 Challenge 类型
	if challenge.Type != "webauthn" {
		return nil, fmt.Errorf("invalid challenge type: %s", challenge.Type)
	}

	// 获取用户 ID
	userID := challenge.UserID
	if userID == "" {
		return nil, fmt.Errorf("user_id not found in challenge")
	}

	logger.Infof("[WebAuthnAuth] 验证成功 - UserID: %s, ChallengeID: %s", userID, challengeID)

	return &AuthResult{
		ProviderID: userID,
		RawData:    fmt.Sprintf(`{"challenge_id":"%s","user_id":"%s"}`, challengeID, userID),
	}, nil
}

// GetRPID 获取 RP ID（用于前端配置）
func (a *WebAuthnAuthenticator) GetRPID() string {
	if a.webauthn == nil {
		return ""
	}
	return a.webauthn.GetRPID()
}
