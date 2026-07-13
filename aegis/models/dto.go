package models

// WebAuthnBeginResponse WebAuthn 流程开始响应（注册或验证）
type WebAuthnBeginResponse struct {
	ChallengeID string `json:"challenge_id"`
	Options     any    `json:"options"`
}

// WebAuthnCredentialInfo 凭证信息
type WebAuthnCredentialInfo struct {
	ID        []byte `json:"id"`
	SignCount uint32 `json:"sign_count"`
}

// RegisterWebAuthnRequest WebAuthn 注册请求
type RegisterWebAuthnRequest struct {
	OpenID          string
	CredentialID    string
	PublicKey       string
	AAGUID          string
	Transport       []string
	AttestationType string
}
