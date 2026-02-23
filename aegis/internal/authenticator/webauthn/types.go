package webauthn

import (
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// RegistrationBeginResponse 注册开始响应
type RegistrationBeginResponse struct {
	Options     *protocol.CredentialCreation `json:"options"`
	ChallengeID string                       `json:"challenge_id"`
}

// LoginBeginResponse 登录开始响应
type LoginBeginResponse struct {
	Options     *protocol.CredentialAssertion `json:"options"`
	ChallengeID string                        `json:"challenge_id"`
}

// SessionData WebAuthn 会话数据（存储在 Redis 中）
type SessionData struct {
	OpenID      string                `json:"openid"`
	Challenge   string                `json:"challenge"`
	SessionData *webauthn.SessionData `json:"session_data"`
}
