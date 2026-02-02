package authenticate

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"

	"github.com/heliannuuthus/helios/internal/aegis/cache"
	"github.com/heliannuuthus/helios/internal/config"
	"github.com/heliannuuthus/helios/pkg/logger"
)

// ErrUserNotFound 用户不存在
var ErrUserNotFound = errors.New("user not found")

// ErrEmailNotVerified 邮箱未验证
var ErrEmailNotVerified = errors.New("email not verified")

// EmailAuthenticator 邮箱验证码认证器
type EmailAuthenticator struct {
	cache  *cache.Manager
	sender EmailSender
}

// NewEmailAuthenticator 创建邮箱认证器
func NewEmailAuthenticator(cm *cache.Manager, sender EmailSender) *EmailAuthenticator {
	return &EmailAuthenticator{
		cache:  cm,
		sender: sender,
	}
}

// Type 返回认证器类型
func (*EmailAuthenticator) Type() AuthType {
	return AuthTypeEmail
}

// Supports 判断是否支持该 connection
func (*EmailAuthenticator) Supports(connection string) bool {
	return connection == "email"
}

// Authenticate 执行认证（验证验证码）
// PIAM 域邮箱登录规则：
// 1. 用户必须已存在（通过邮箱查找）
// 2. 用户邮箱必须已验证（email_verified = true）
// 3. 验证码必须正确
func (a *EmailAuthenticator) Authenticate(ctx context.Context, _ string, data map[string]any) (*AuthResult, error) {
	// 1. 获取 email 和 code
	email, ok := data["email"].(string)
	if !ok || email == "" {
		return nil, errors.New("email is required")
	}

	code, ok := data["code"].(string)
	if !ok || code == "" {
		return nil, errors.New("code is required")
	}

	// 2. 查找用户（必须存在且邮箱已验证）
	user, err := a.cache.FindUserByEmail(ctx, email)
	if err != nil {
		logger.Warnf("[EmailAuth] 用户不存在 - Email: %s, Error: %v", email, err)
		return nil, ErrUserNotFound
	}

	// 3. 检查邮箱是否已验证
	if !user.EmailVerified {
		logger.Warnf("[EmailAuth] 邮箱未验证 - Email: %s, OpenID: %s", email, user.OpenID)
		return nil, ErrEmailNotVerified
	}

	// 4. 验证验证码
	if err := a.cache.VerifyOTP(ctx, a.otpKey(email), code); err != nil {
		return nil, fmt.Errorf("invalid or expired code: %w", err)
	}

	logger.Infof("[EmailAuth] 验证成功 - Email: %s, OpenID: %s", email, user.OpenID)

	// 返回用户的 OpenID 作为 ProviderID，用于后续查找
	return &AuthResult{
		ProviderID: user.OpenID,
		RawData:    fmt.Sprintf(`{"email":"%s","openid":"%s"}`, email, user.OpenID),
	}, nil
}

// SendCode 发送验证码
func (a *EmailAuthenticator) SendCode(ctx context.Context, email string) error {
	// 生成 6 位数字验证码
	code, err := generateOTP(6)
	if err != nil {
		return fmt.Errorf("generate otp failed: %w", err)
	}

	// 保存到缓存（TTL 由 cache 配置管理）
	if err := a.cache.SaveOTP(ctx, a.otpKey(email), code); err != nil {
		return fmt.Errorf("save otp failed: %w", err)
	}

	// 发送邮件
	otpExpiresIn := config.GetAegisOTPExpiresIn()
	subject := "验证码"
	body := fmt.Sprintf("您的验证码是：%s，有效期 %d 分钟。", code, int(otpExpiresIn.Minutes()))
	if err := a.sender.Send(ctx, email, subject, body); err != nil {
		return fmt.Errorf("send email failed: %w", err)
	}

	logger.Infof("[EmailAuth] 发送验证码成功 - Email: %s", email)
	return nil
}

// otpKey 生成 OTP 缓存 key
func (a *EmailAuthenticator) otpKey(email string) string {
	return "email:" + email
}

// generateOTP 生成指定位数的数字验证码
func generateOTP(length int) (string, error) {
	digits := "0123456789"
	result := make([]byte, length)
	for i := 0; i < length; i++ {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(digits))))
		if err != nil {
			return "", err
		}
		result[i] = digits[idx.Int64()]
	}
	return string(result), nil
}
