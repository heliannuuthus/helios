package factor

import (
	"context"
	"fmt"

	"github.com/heliannuuthus/aegis/internal/types"
)

var (
	_ Provider = (*TOTPFactor)(nil)
)

type TOTPVerifier interface {
	VerifyCode(ctx context.Context, openid, code string) (bool, error)
}

// TOTPFactor TOTP 认证因子
type TOTPFactor struct {
	verifier TOTPVerifier
}

// NewTOTPFactor 创建 TOTP 认证因子
func NewTOTPFactor(verifier TOTPVerifier) *TOTPFactor {
	return &TOTPFactor{
		verifier: verifier,
	}
}

// Type 返回因子类型标识
func (*TOTPFactor) Type() string {
	return TypeTOTP
}

func (p *TOTPFactor) Initiate(_ context.Context, challenge *types.Challenge) error {
	if challenge.Channel == "" {
		return fmt.Errorf("user_id is required for totp")
	}
	return nil
}

// Verify 验证 TOTP 验证码
// proof: TOTP 码
// params[0]: openid (string)
func (p *TOTPFactor) Verify(ctx context.Context, proof string, params ...any) (bool, error) {
	if proof == "" {
		return false, nil
	}

	if len(params) < 1 {
		return false, nil
	}
	openid, ok := params[0].(string)
	if !ok || openid == "" {
		return false, nil
	}

	return p.verifier.VerifyCode(ctx, openid, proof)
}

// Prepare 准备前端公开配置
func (*TOTPFactor) Prepare() *types.ConnectionConfig {
	return &types.ConnectionConfig{
		Connection: TypeTOTP,
	}
}
