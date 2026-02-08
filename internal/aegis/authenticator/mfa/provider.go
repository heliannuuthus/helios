// Package mfa provides MFA (Multi-Factor Authentication) provider implementations.
package mfa

import (
	"context"

	"github.com/heliannuuthus/helios/internal/aegis/types"
)

// MFA 类型常量
const (
	TypeEmailOTP = "email-otp" // 邮件验证码
	TypeTOTP     = "totp"      // 时间动态口令
	TypeWebAuthn = "webauthn"  // WebAuthn/FIDO2
)

// Provider MFA 提供者接口
type Provider interface {
	// Type 返回 MFA 类型标识
	Type() string

	// Verify 验证 MFA 凭证
	// proof: 验证凭证（OTP code / WebAuthn response 等）
	// params: 额外参数（如 userID、challengeID、http.Request 等）
	Verify(ctx context.Context, proof string, params ...any) (bool, error)

	// Prepare 准备前端所需的公开配置
	Prepare() *types.ConnectionConfig
}
