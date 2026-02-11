package models

import (
	"time"
)

// CredentialType 凭证类型
type CredentialType string

const (
	CredentialTypeTOTP     CredentialType = "totp"
	CredentialTypeWebAuthn CredentialType = "webauthn"
	CredentialTypePasskey  CredentialType = "passkey"
)

// UserCredential 用户安全凭证
type UserCredential struct {
	// 主键
	ID uint `gorm:"primaryKey;autoIncrement;column:_id"`
	// 固定长度字段（高频访问）
	OpenID       string  `gorm:"column:openid;size:64;not null;index"`
	CredentialID *string `gorm:"column:credential_id;size:256;uniqueIndex"`
	Type         string  `gorm:"column:type;size:32;not null"`
	Enabled      bool    `gorm:"column:enabled;not null;default:0"`
	// 时间戳
	LastUsedAt *time.Time `gorm:"column:last_used_at"`
	CreatedAt  time.Time  `gorm:"column:created_at;not null"`
	UpdatedAt  time.Time  `gorm:"column:updated_at;not null"`
	// 变长字段
	Secret string `gorm:"column:secret;size:2048;not null"`
}

func (UserCredential) TableName() string {
	return "t_user_credential"
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

// CredentialSummary 凭证摘要（不含敏感信息）
type CredentialSummary struct {
	ID           uint       `json:"id"`
	Type         string     `json:"type"`
	CredentialID string     `json:"credential_id,omitempty"` // WebAuthn 专用
	Enabled      bool       `json:"enabled"`
	LastUsedAt   *time.Time `json:"last_used_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
}

// MFAStatus 用户 MFA 状态
type MFAStatus struct {
	TOTPEnabled   bool `json:"totp_enabled"`
	WebAuthnCount int  `json:"webauthn_count"`
	PasskeyCount  int  `json:"passkey_count"`
}
