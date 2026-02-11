package factor

import (
	"context"
	"fmt"

	"github.com/heliannuuthus/helios/internal/aegis/types"
)

// TOTPVerifier TOTP 验证接口
type TOTPVerifier interface {
	Verify(ctx context.Context, openid, code string) (bool, error)
}

// TOTPProvider TOTP 认证因子 Provider
type TOTPProvider struct {
	verifier TOTPVerifier
}

// NewTOTPProvider 创建 TOTP 认证因子 Provider
func NewTOTPProvider(verifier TOTPVerifier) *TOTPProvider {
	return &TOTPProvider{
		verifier: verifier,
	}
}

// Type 返回因子类型标识
func (*TOTPProvider) Type() string {
	return TypeTOTP
}

// Initiate 校验 user_id 并构建 Challenge（TOTP 无副作用）
// channel: user_id
// params: clientID, audience, bizType
func (p *TOTPProvider) Initiate(ctx context.Context, channel string, params ...any) (*InitiateResult, error) {
	if channel == "" {
		return nil, fmt.Errorf("user_id is required for totp")
	}

	ip, err := ParseInitiateParams(params...)
	if err != nil {
		return nil, err
	}

	challenge := NewChallenge(types.ChannelTypeTOTP, channel, ip)
	return &InitiateResult{Challenge: challenge}, nil
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
