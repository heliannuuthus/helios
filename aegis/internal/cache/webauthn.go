package cache

import (
	"encoding/base64"

	"github.com/go-json-experiment/json"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/heliannuuthus/helios/hermes/models"
)

// StoredWebAuthnCredential 存储的 WebAuthn 凭证（用于缓存层传递）
// 与 webauthn 包中的定义保持一致
type StoredWebAuthnCredential struct {
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

// ToWebAuthnCredential 转换为 webauthn.Credential
func (s *StoredWebAuthnCredential) ToWebAuthnCredential() webauthn.Credential {
	return webauthn.Credential{
		ID:              s.ID,
		PublicKey:       s.PublicKey,
		AttestationType: s.AttestationType,
		Transport:       s.Transport,
		Flags:           s.Flags,
		Authenticator: webauthn.Authenticator{
			AAGUID:       s.Authenticator.AAGUID,
			SignCount:    s.Authenticator.SignCount,
			CloneWarning: s.Authenticator.CloneWarning,
		},
	}
}

// FromWebAuthnCredential 从 webauthn.Credential 转换
func FromWebAuthnCredential(cred *webauthn.Credential) *StoredWebAuthnCredential {
	return &StoredWebAuthnCredential{
		ID:              cred.ID,
		PublicKey:       cred.PublicKey,
		AttestationType: cred.AttestationType,
		Transport:       cred.Transport,
		Flags:           cred.Flags,
		Authenticator: StoredAuthenticator{
			AAGUID:       cred.Authenticator.AAGUID,
			SignCount:    cred.Authenticator.SignCount,
			CloneWarning: cred.Authenticator.CloneWarning,
		},
	}
}

// ParseStoredWebAuthnCredential 从数据库凭证解析 StoredWebAuthnCredential
func ParseStoredWebAuthnCredential(cred *models.UserCredential) (*StoredWebAuthnCredential, error) {
	var stored StoredWebAuthnCredential
	if err := json.Unmarshal([]byte(cred.Secret), &stored); err != nil {
		return nil, err
	}
	return &stored, nil
}

// SerializeWebAuthnCredential 序列化 WebAuthn 凭证为 JSON 字符串
func SerializeWebAuthnCredential(cred *StoredWebAuthnCredential) (string, error) {
	data, err := json.Marshal(cred)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// EncodeCredentialID 编码凭证 ID 为 Base64URL 字符串
func EncodeCredentialID(id []byte) string {
	return base64.RawURLEncoding.EncodeToString(id)
}

// DecodeCredentialID 解码 Base64URL 字符串为凭证 ID
func DecodeCredentialID(encoded string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(encoded)
}
