package webauthn

import (
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// RegistrationBeginRequest 注册开始请求
type RegistrationBeginRequest struct {
	UserID string `json:"user_id" binding:"required"` // 用户 OpenID
}

// RegistrationBeginResponse 注册开始响应
type RegistrationBeginResponse struct {
	Options     *protocol.CredentialCreation `json:"options"`      // WebAuthn 选项
	ChallengeID string                       `json:"challenge_id"` // Challenge ID（用于后续验证）
}

// RegistrationFinishRequest 注册完成请求
type RegistrationFinishRequest struct {
	ChallengeID string `json:"challenge_id" binding:"required"` // Challenge ID
	// 前端传来的 attestation response（JSON）
	// 包含 id, rawId, response, type 等字段
}

// RegistrationFinishResponse 注册完成响应
type RegistrationFinishResponse struct {
	Success      bool   `json:"success"`
	CredentialID string `json:"credential_id,omitempty"` // 新创建的凭证 ID
	Message      string `json:"message,omitempty"`
}

// LoginBeginRequest 登录开始请求
type LoginBeginRequest struct {
	UserID string `json:"user_id,omitempty"` // 用户 OpenID（可选，discoverable credential 时不需要）
}

// LoginBeginResponse 登录开始响应
type LoginBeginResponse struct {
	Options     *protocol.CredentialAssertion `json:"options"`      // WebAuthn 选项
	ChallengeID string                        `json:"challenge_id"` // Challenge ID
}

// LoginFinishRequest 登录完成请求
type LoginFinishRequest struct {
	ChallengeID string `json:"challenge_id" binding:"required"` // Challenge ID
	// 前端传来的 assertion response（JSON）
}

// LoginFinishResponse 登录完成响应
type LoginFinishResponse struct {
	Success bool   `json:"success"`
	UserID  string `json:"user_id,omitempty"` // 认证成功的用户 OpenID
	Message string `json:"message,omitempty"`
}

// StoredCredential 存储的凭证信息（用于 webauthn 包内部使用）
// 注意：实际存储使用 cache.StoredWebAuthnCredential
type StoredCredential = struct {
	ID              []byte                            `json:"id"`
	PublicKey       []byte                            `json:"public_key"`
	AttestationType string                            `json:"attestation_type"`
	Transport       []protocol.AuthenticatorTransport `json:"transport"`
	Flags           webauthn.CredentialFlags          `json:"flags"`
	Authenticator   StoredAuthenticator               `json:"authenticator"`
}

// StoredAuthenticator 存储的认证器信息
type StoredAuthenticator struct {
	AAGUID       []byte `json:"aaguid"`
	SignCount    uint32 `json:"sign_count"`
	CloneWarning bool   `json:"clone_warning"`
}

// SessionData WebAuthn 会话数据（存储在 Redis 中）
type SessionData struct {
	UserID      string                `json:"user_id"`
	Challenge   string                `json:"challenge"`
	SessionData *webauthn.SessionData `json:"session_data"`
}
