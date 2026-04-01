package models

import "time"

// CredentialType 凭证类型
type CredentialType string

const (
	CredentialTypeTOTP     CredentialType = "totp"
	CredentialTypeWebAuthn CredentialType = "webauthn"
	CredentialTypePasskey  CredentialType = "passkey"
)

// UserCredential 用户安全凭证（从 proto 转换）
type UserCredential struct {
	ID           uint       `json:"_id"`
	OpenID       string     `json:"openid"`
	CredentialID *string    `json:"credential_id,omitempty"`
	Type         string     `json:"type"`
	Enabled      bool       `json:"enabled"`
	LastUsedAt   *time.Time `json:"last_used_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	Secret       string     `json:"-"`
}

// MFAStatus 用户 MFA 状态
type MFAStatus struct {
	TOTPEnabled   bool `json:"totp_enabled"`
	WebAuthnCount int  `json:"webauthn_count"`
	PasskeyCount  int  `json:"passkey_count"`
}

// TOTPSecret TOTP 凭证数据结构（存储在 secret JSON 中）
type TOTPSecret struct {
	Secret string `json:"secret"` // Base32 编码的密钥
}

// WebAuthnSecret WebAuthn 凭证数据结构（存储在 secret JSON 中）
type WebAuthnSecret struct {
	PublicKey       string   `json:"public_key"`       // Base64 编码的公钥
	SignCount       uint32   `json:"sign_count"`       // 签名计数器
	AAGUID          string   `json:"aaguid"`           // 认证器 GUID
	Transport       []string `json:"transport"`        // 传输方式：usb/nfc/ble/internal
	AttestationType string   `json:"attestation_type"` // 认证类型：none/direct/indirect
}

// CredentialSummary 凭证摘要
type CredentialSummary struct {
	ID           uint       `json:"id"`
	Type         string     `json:"type"`
	CredentialID string     `json:"credential_id,omitempty"`
	Enabled      bool       `json:"enabled"`
	LastUsedAt   *time.Time `json:"last_used_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
}
