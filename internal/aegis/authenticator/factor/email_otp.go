package factor

import (
	"context"
	"fmt"
	"net/mail"

	"github.com/heliannuuthus/helios/internal/aegis/cache"
	"github.com/heliannuuthus/helios/internal/aegis/types"
	"github.com/heliannuuthus/helios/pkg/helperutil"
	"github.com/heliannuuthus/helios/pkg/logger"
	"github.com/heliannuuthus/helios/pkg/throttle"
)

// EmailSender 邮件发送接口
type EmailSender interface {
	SendCode(ctx context.Context, email, code string) error
}

// EmailOTPProvider 邮件验证码认证因子 Provider
type EmailOTPProvider struct {
	emailSender EmailSender
	cache       *cache.Manager
	throttler   *throttle.Throttler
}

// NewEmailOTPProvider 创建邮件验证码认证因子 Provider
func NewEmailOTPProvider(emailSender EmailSender, cache *cache.Manager, throttler *throttle.Throttler) *EmailOTPProvider {
	return &EmailOTPProvider{
		emailSender: emailSender,
		cache:       cache,
		throttler:   throttler,
	}
}

// Type 返回因子类型标识
func (*EmailOTPProvider) Type() string {
	return TypeEmailOTP
}

// Initiate 校验邮箱格式、限流检查、发送验证码、构建 Challenge
// channel: 邮箱地址
// params: clientID, audience, bizType
func (p *EmailOTPProvider) Initiate(ctx context.Context, channel string, params ...any) (*InitiateResult, error) {
	// 1. 校验邮箱格式
	if _, err := mail.ParseAddress(channel); err != nil {
		return nil, fmt.Errorf("invalid email format: %s", channel)
	}

	// 2. 解析通用参数
	ip, err := ParseInitiateParams(params...)
	if err != nil {
		return nil, err
	}

	// 3. 构建 Challenge
	challenge := NewChallenge(types.ChannelTypeEmailOTP, channel, ip)

	// 4. 限流检查
	if retryAfter := p.checkRateLimit(ctx, challenge); retryAfter > 0 {
		return &InitiateResult{Challenge: challenge, RetryAfter: retryAfter}, nil
	}

	// 5. 发送 OTP
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

// checkRateLimit 限流检查（channel 维度）
// 返回 retryAfter > 0 表示被限流
func (p *EmailOTPProvider) checkRateLimit(ctx context.Context, challenge *types.Challenge) int {
	if p.throttler == nil {
		return 0
	}

	limits := p.cache.GetChallengeRateLimits(ctx, challenge.Audience, challenge.Type)

	channelKey := types.RateLimitKeyPrefixCreate + challenge.Audience + ":" + challenge.Type + ":" + challenge.Channel
	result, err := p.throttler.Allow(ctx, channelKey, limits)
	if err != nil {
		logger.Warnf("[EmailOTP] 限流检查失败: %v", err)
		return 0 // 限流检查失败不阻塞业务
	}
	if !result.Allowed {
		return result.RetryAfter
	}

	return 0
}

// sendOTP 发送邮件验证码
func (p *EmailOTPProvider) sendOTP(ctx context.Context, email, challengeID string) error {
	code, err := helperutil.GenerateOTP(6)
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

	logger.Infof("[EmailOTP] 已发送验证码 - Email: %s", helperutil.MaskEmail(email))
	return nil
}
