// Package totp provides TOTP (Time-based One-Time Password) verification.
package totp

import (
	"context"

	"github.com/heliannuuthus/aegis/contract"
	"github.com/heliannuuthus/aegis/models"
	"github.com/heliannuuthus/pkg/logger"
)

type Verifier struct {
	verifier contract.TOTPVerifier
}

func NewVerifier(verifier contract.TOTPVerifier) *Verifier {
	return &Verifier{
		verifier: verifier,
	}
}

// Verify 验证 TOTP 码
// 实现 factor.TOTPVerifier 接口
func (v *Verifier) Verify(ctx context.Context, openid, code string) (bool, error) {
	if openid == "" || code == "" {
		return false, nil
	}

	err := v.verifier.VerifyTOTP(ctx, &models.VerifyTOTPRequest{
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
