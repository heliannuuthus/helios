package models

// PasswordStoreCredential 密码存储凭证（IDP 身份解析结果）
type PasswordStoreCredential struct {
	OpenID       string
	PasswordHash string
	Nickname     string
	Email        string
	Picture      string
	Status       int8
}

// TOTPSetupRequest TOTP 设置请求
type TOTPSetupRequest struct {
	OpenID  string
	AppName string
}

// TOTPSetupResponse TOTP 设置响应
type TOTPSetupResponse struct {
	Secret       string `json:"secret"`
	OTPAuthURI   string `json:"otpauth_uri"`
	CredentialID uint   `json:"credential_id"`
}

// ConfirmTOTPRequest TOTP 确认请求
type ConfirmTOTPRequest struct {
	OpenID       string
	CredentialID uint
	Code         string
}

// VerifyTOTPRequest TOTP 验证请求
type VerifyTOTPRequest struct {
	OpenID string
	Code   string
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
