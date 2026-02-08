package mfa

import (
	"context"

	"github.com/heliannuuthus/helios/internal/aegis/cache"
	"github.com/heliannuuthus/helios/internal/aegis/types"
	"github.com/heliannuuthus/helios/pkg/helperutil"
	"github.com/heliannuuthus/helios/pkg/logger"
)

// EmailSender 邮件发送接口
type EmailSender interface {
	SendCode(ctx context.Context, email, code string) error
}

// EmailOTPProvider 邮件验证码 MFA Provider
type EmailOTPProvider struct {
	emailSender EmailSender
	cache       *cache.Manager
}

// NewEmailOTPProvider 创建邮件验证码 MFA Provider
func NewEmailOTPProvider(emailSender EmailSender, cache *cache.Manager) *EmailOTPProvider {
	return &EmailOTPProvider{
		emailSender: emailSender,
		cache:       cache,
	}
}

// Type 返回 MFA 类型标识
func (*EmailOTPProvider) Type() string {
	return TypeEmailOTP
}

// Verify 验证邮件验证码
// proof: OTP 验证码
// params[0]: challengeID (string) - 用于从 cache 获取已存储的 OTP
func (p *EmailOTPProvider) Verify(ctx context.Context, proof string, params ...any) (bool, error) {
	if proof == "" {
		return false, nil
	}

	if len(params) < 1 {
		return false, nil
	}
	challengeID, ok := params[0].(string)
	if !ok || challengeID == "" {
		return false, nil
	}

	otpKey := "email-otp:" + challengeID
	storedCode, err := p.cache.GetOTP(ctx, otpKey)
	if err != nil {
		return false, nil
	}

	if storedCode != proof {
		return false, nil
	}

	// 验证成功，删除 OTP
	_ = p.cache.DeleteOTP(ctx, otpKey) //nolint:errcheck

	return true, nil
}

// Prepare 准备前端公开配置
func (*EmailOTPProvider) Prepare() *types.ConnectionConfig {
	return &types.ConnectionConfig{
		Connection: TypeEmailOTP,
	}
}

// SendOTP 发送邮件验证码
// 返回 challengeID，用于后续验证
func (p *EmailOTPProvider) SendOTP(ctx context.Context, email, challengeID string) error {
	code, err := helperutil.GenerateOTP(6)
	if err != nil {
		return err
	}

	otpKey := "email-otp:" + challengeID
	if err := p.cache.SaveOTP(ctx, otpKey, code); err != nil {
		return err
	}

	if p.emailSender != nil {
		if err := p.emailSender.SendCode(ctx, email, code); err != nil {
			logger.Errorf("[EmailOTP] 发送邮件失败: %v", err)
			return err
		}
	}

	logger.Infof("[EmailOTP] 已发送验证码 - Email: %s", helperutil.MaskEmail(email))
	return nil
}
