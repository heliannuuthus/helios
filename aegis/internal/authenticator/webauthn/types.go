package webauthn

import "github.com/go-webauthn/webauthn/protocol"

// RegistrationOptions 注册初始化响应
type RegistrationOptions struct {
	Options    *protocol.CredentialCreation `json:"options"`
	CeremonyID string                       `json:"challenge_id"`
}

// AuthenticationOptions 认证初始化响应
type AuthenticationOptions struct {
	Options    *protocol.CredentialAssertion `json:"options"`
	CeremonyID string                        `json:"challenge_id"`
}
