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

// EmailSender 邮件发送接口
type EmailSender interface {
	SendCode(ctx context.Context, email, code string) error
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

// Initiate 校验邮箱格式、发送验证码
// channel: 邮箱地址
// params: clientID, audience, bizType
// 注意：限流检查已移至 FactorAuthenticator.Initiate
func (p *EmailOTPProvider) Initiate(ctx context.Context, channel string, params ...any) (*InitiateResult, error) {
	// 1. 校验邮箱格式
	if _, err := mail.ParseAddress(channel); err != nil {
		return nil, fmt.Errorf("invalid email format: %s", channel)
	}

	// 2. 解析通用参数
	initiateParams, err := ParseInitiateParams(params...)
	if err != nil {
		return nil, err
	}

	// 3. 构建临时 Challenge（仅用于生成 ID 和存储 OTP）
	challenge := NewChallenge(types.ChannelTypeEmailOTP, channel, initiateParams)

	// 4. 发送 OTP
	if err := p.sendOTP(ctx, channel, challenge.ID); err != nil {
		return nil, err
	}

	return &InitiateResult{Challenge: challenge}, nil
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
func (p *EmailOTPProvider) sendOTP(ctx context.Context, email, challengeID string) error {
	code, err := helpers.GenerateOTP(6)
	if err != nil {
		return err
	}

	otpKey := types.CacheKeyPrefixEmailOTP + challengeID
	if err := p.cache.SaveOTP(ctx, otpKey, code); err != nil {
		return err
	}

	if p.emailSender != nil {
		if err := p.emailSender.SendCode(ctx, email, code); err != nil {
			logger.Errorf("[EmailOTP] 发送邮件失败: %v", err)
			return err
		}
	}

	logger.Infof("[EmailOTP] 已发送验证码 - Email: %s", helpers.MaskEmail(email))
	return nil
}
