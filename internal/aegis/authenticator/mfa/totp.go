package mfa

import (
	"context"

	"github.com/heliannuuthus/helios/internal/aegis/types"
)

// TOTPVerifier TOTP 验证接口
type TOTPVerifier interface {
	Verify(ctx context.Context, openid, code string) (bool, error)
}

// TOTPProvider TOTP MFA Provider
type TOTPProvider struct {
	verifier TOTPVerifier
}

// NewTOTPProvider 创建 TOTP MFA Provider
func NewTOTPProvider(verifier TOTPVerifier) *TOTPProvider {
	return &TOTPProvider{
		verifier: verifier,
	}
}

// Type 返回 MFA 类型标识
func (*TOTPProvider) Type() string {
	return TypeTOTP
}

// Verify 验证 TOTP 验证码
// proof: TOTP 码
// params[0]: openid (string)
func (p *TOTPProvider) Verify(ctx context.Context, proof string, params ...any) (bool, error) {
	if proof == "" {
		return false, nil
	}

	if p.verifier == nil {
		return false, nil
	}

	if len(params) < 1 {
		return false, nil
	}
	openid, ok := params[0].(string)
	if !ok || openid == "" {
		return false, nil
	}

	return p.verifier.Verify(ctx, openid, proof)
}

// Prepare 准备前端公开配置
func (*TOTPProvider) Prepare() *types.ConnectionConfig {
	return &types.ConnectionConfig{
		Connection: TypeTOTP,
	}
}
