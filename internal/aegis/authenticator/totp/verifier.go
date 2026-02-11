// Package totp provides TOTP (Time-based One-Time Password) verification.
package totp

import (
	"context"

	"github.com/heliannuuthus/helios/internal/hermes"
	"github.com/heliannuuthus/helios/pkg/logger"
)

// Verifier TOTP 验证器
// 通过 hermes.CredentialService 读取用户 TOTP 密钥并验证
type Verifier struct {
	credentialSvc *hermes.CredentialService
}

// NewVerifier 创建 TOTP 验证器
func NewVerifier(credentialSvc *hermes.CredentialService) *Verifier {
	return &Verifier{
		credentialSvc: credentialSvc,
	}
}

// Verify 验证 TOTP 码
// 实现 factor.TOTPVerifier 接口
func (v *Verifier) Verify(ctx context.Context, openid, code string) (bool, error) {
	if openid == "" || code == "" {
		return false, nil
	}

	err := v.credentialSvc.VerifyTOTP(ctx, &hermes.VerifyTOTPRequest{
		OpenID: openid,
		Code:   code,
	})
	if err != nil {
		logger.Debugf("[TOTP] 验证失败 - OpenID: %s, Error: %v", openid, err)
		return false, nil
	}

	logger.Infof("[TOTP] 验证成功 - OpenID: %s", openid)
	return true, nil
}
