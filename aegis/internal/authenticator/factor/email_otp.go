package factor

import (
	"context"
	"fmt"
	"net/mail"

	"github.com/heliannuuthus/helios/aegis/internal/cache"
	"github.com/heliannuuthus/helios/aegis/internal/types"
	"github.com/heliannuuthus/helios/pkg/helpers"
	"github.com/heliannuuthus/helios/pkg/logger"
)

var _ Provider = (*EmailOTPProvider)(nil)

// EmailSender 邮件发送接口
// scene 由业务层根据 challenge.Type 映射，Sender 实现按 scene 选择模板渲染
type EmailSender interface {
	SendCode(ctx context.Context, email, code, scene string) error
}

// EmailOTPProvider 邮件验证码认证因子 Provider
type EmailOTPProvider struct {
	emailSender EmailSender
	cache       *cache.Manager
}

// NewEmailOTPProvider 创建邮件验证码认证因子 Provider
func NewEmailOTPProvider(emailSender EmailSender, cache *cache.Manager) *EmailOTPProvider {
	return &EmailOTPProvider{
		emailSender: emailSender,
		cache:       cache,
	}
}

// Type 返回因子类型标识
func (*EmailOTPProvider) Type() string {
	return TypeEmailOTP
}

func (p *EmailOTPProvider) Initiate(ctx context.Context, challenge *types.Challenge) error {
	if _, err := mail.ParseAddress(challenge.Channel); err != nil {
		return fmt.Errorf("invalid email format: %s", challenge.Channel)
	}
	return p.sendOTP(ctx, challenge)
}

// Verify 验证邮件验证码
// proof: OTP 验证码
// params[0]: channel (string) - 邮箱地址（未使用，但统一传入）
// params[1]: challengeID (string) - 用于从 cache 获取已存储的 OTP
func (p *EmailOTPProvider) Verify(ctx context.Context, proof string, params ...any) (bool, error) {
	if proof == "" {
		return false, nil
	}

	if len(params) < 2 {
		return false, nil
	}
	challengeID, ok := params[1].(string)
	if !ok || challengeID == "" {
		return false, nil
	}

	otpKey := types.CacheKeyPrefixEmailOTP + challengeID
	storedCode, err := p.cache.GetOTP(ctx, otpKey)
	if err != nil {
		return false, nil
	}

	if storedCode != proof {
		return false, nil
	}

	// 验证成功，删除 OTP
	if err := p.cache.DeleteOTP(ctx, otpKey); err != nil {
		logger.Warnf("[EmailOTP] 删除 OTP 失败: %v", err)
	}

	return true, nil
}

// Prepare 准备前端公开配置
func (*EmailOTPProvider) Prepare() *types.ConnectionConfig {
	return &types.ConnectionConfig{
		Connection: TypeEmailOTP,
	}
}

// ==================== 内部方法 ====================

// sendOTP 发送邮件验证码
func (p *EmailOTPProvider) sendOTP(ctx context.Context, ch *types.Challenge) error {
	code, err := helpers.GenerateOTP(6)
	if err != nil {
		return err
	}

	otpKey := types.CacheKeyPrefixEmailOTP + ch.ID
	if err := p.cache.SaveOTP(ctx, otpKey, code); err != nil {
		return err
	}

	if p.emailSender != nil {
		if err := p.emailSender.SendCode(ctx, ch.Channel, code, otpScene(ch.Type)); err != nil {
			logger.Errorf("[EmailOTP] 发送邮件失败: %v", err)
			return err
		}
	}

	logger.Infof("[EmailOTP] 已发送验证码 - Email: %s", helpers.MaskEmail(ch.Channel))
	return nil
}

// otpScene 将业务类型映射到邮件模板场景
func otpScene(typ string) string {
	switch typ {
	case "register":
		return "otp_register"
	case "reset_password", "forget_password":
		return "otp_reset_password"
	case "bind_email":
		return "otp_bind_email"
	case "change_email":
		return "otp_change_email"
	case "mfa":
		return "otp_mfa"
	case "verify_identity":
		return "otp_verify_identity"
	case "delete_account":
		return "otp_delete_account"
	default:
		return "otp_login"
	}
}
