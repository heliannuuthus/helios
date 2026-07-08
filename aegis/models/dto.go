package models

// PasswordAuth 密码存储凭证（IDP 身份解析结果）
type PasswordAuth struct {
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
	UID        string `json:"uid"`
	Secret     string `json:"secret"`
	OTPAuthURI string `json:"otpauth_uri"`
}

// ConfirmTOTPRequest TOTP 确认请求
type ConfirmTOTPRequest struct {
	OpenID string
	UID    string
	Code   string
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
