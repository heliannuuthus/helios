// Package factor provides authentication factor provider implementations.
package factor

import (
	"context"

	"github.com/heliannuuthus/helios/aegis/internal/types"
)

// 因子类型常量
const (
	TypeEmailOTP = "email_otp" // 邮件验证码
	TypeTOTP     = "totp"      // 时间动态口令
	TypeWebAuthn = "webauthn"  // WebAuthn/FIDO2
)

// Provider 认证因子提供者接口
type Provider interface {
	// Type 返回因子类型标识
	Type() string

	// Initiate 执行副作用（发邮件等），所有上下文数据从 challenge 引用获取
	Initiate(ctx context.Context, challenge *types.Challenge) error

	// Verify 验证认证因子凭证
	// proof: 验证凭证（OTP code / WebAuthn response 等）
	// params: 额外参数（如 challengeID、channel 等）
	Verify(ctx context.Context, proof string, params ...any) (bool, error)

	// Prepare 准备前端所需的公开配置
	Prepare() *types.ConnectionConfig
}
