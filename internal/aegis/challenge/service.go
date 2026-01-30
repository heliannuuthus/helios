package challenge

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"time"

	"github.com/heliannuuthus/helios/internal/aegis/captcha"
	"github.com/heliannuuthus/helios/internal/aegis/types"
	"github.com/heliannuuthus/helios/pkg/logger"
)

// 默认过期时间
const (
	DefaultCaptchaTTL = 5 * time.Minute
	DefaultTOTPTTL    = 5 * time.Minute
	DefaultEmailTTL   = 5 * time.Minute
	DefaultOTPLength  = 6
)

// CacheStore Challenge 缓存存储接口
type CacheStore interface {
	SaveChallenge(ctx context.Context, challenge *types.Challenge) error
	GetChallenge(ctx context.Context, challengeID string) (*types.Challenge, error)
	DeleteChallenge(ctx context.Context, challengeID string) error

	// OTP 相关（email 验证码）
	SaveOTP(ctx context.Context, key, code string) error
	GetOTP(ctx context.Context, key string) (string, error)
	DeleteOTP(ctx context.Context, key string) error
}

// EmailSender 邮件发送接口
type EmailSender interface {
	SendCode(ctx context.Context, email, code string) error
}

// TOTPVerifier TOTP 验证接口
type TOTPVerifier interface {
	Verify(ctx context.Context, userID, code string) (bool, error)
}

// Service Challenge 服务
type Service struct {
	cache        CacheStore
	captcha      captcha.Verifier
	emailSender  EmailSender
	totpVerifier TOTPVerifier
}

// ServiceConfig 服务配置
type ServiceConfig struct {
	Cache        CacheStore
	Captcha      captcha.Verifier
	EmailSender  EmailSender
	TOTPVerifier TOTPVerifier
}

// NewService 创建 Challenge 服务
func NewService(cfg *ServiceConfig) *Service {
	return &Service{
		cache:        cfg.Cache,
		captcha:      cfg.Captcha,
		emailSender:  cfg.EmailSender,
		totpVerifier: cfg.TOTPVerifier,
	}
}

// Create 创建 Challenge
func (s *Service) Create(ctx context.Context, req *CreateRequest, remoteIP string) (*CreateResponse, error) {
	// 检查是否需要 captcha 前置验证
	if req.Type.RequiresCaptcha() && req.CaptchaToken == "" {
		return nil, &CaptchaRequiredError{
			SiteKey: s.captcha.GetSiteKey(),
		}
	}

	// 验证 captcha token（如果提供）
	if req.CaptchaToken != "" && s.captcha != nil {
		ok, err := s.captcha.Verify(ctx, req.CaptchaToken, remoteIP)
		if err != nil || !ok {
			logger.Warnf("[Challenge] captcha 验证失败: %v", err)
			return nil, fmt.Errorf("captcha verification failed")
		}
	}

	// 根据类型创建 Challenge
	switch req.Type {
	case types.ChallengeTypeCaptcha:
		return s.createCaptchaChallenge(ctx, req)
	case types.ChallengeTypeTOTP:
		return s.createTOTPChallenge(ctx, req)
	case types.ChallengeTypeEmail:
		return s.createEmailChallenge(ctx, req)
	default:
		return nil, fmt.Errorf("unsupported challenge type: %s", req.Type)
	}
}

// Verify 验证 Challenge
func (s *Service) Verify(ctx context.Context, req *VerifyRequest, remoteIP string) (*VerifyResponse, error) {
	// 获取 Challenge
	challenge, err := s.cache.GetChallenge(ctx, req.ChallengeID)
	if err != nil {
		return nil, fmt.Errorf("challenge not found")
	}

	// 检查是否已过期
	if challenge.IsExpired() {
		return nil, fmt.Errorf("challenge expired")
	}

	// 检查是否已验证
	if challenge.Verified {
		return &VerifyResponse{Verified: true}, nil
	}

	// 根据类型验证
	var verified bool
	switch challenge.Type {
	case types.ChallengeTypeCaptcha:
		verified, err = s.verifyCaptcha(ctx, challenge, req, remoteIP)
	case types.ChallengeTypeTOTP:
		verified, err = s.verifyTOTP(ctx, challenge, req)
	case types.ChallengeTypeEmail:
		verified, err = s.verifyEmail(ctx, challenge, req)
	default:
		return nil, fmt.Errorf("unsupported challenge type: %s", challenge.Type)
	}

	if err != nil {
		return nil, err
	}

	if verified {
		// 标记为已验证
		challenge.SetVerified()
		if err := s.cache.SaveChallenge(ctx, challenge); err != nil {
			logger.Warnf("[Challenge] 保存 challenge 失败: %v", err)
		}
	}

	return &VerifyResponse{Verified: verified}, nil
}

// GetChallenge 获取 Challenge 信息
func (s *Service) GetChallenge(ctx context.Context, challengeID string) (*types.Challenge, error) {
	return s.cache.GetChallenge(ctx, challengeID)
}

// GetCaptchaSiteKey 获取 Captcha 站点密钥
func (s *Service) GetCaptchaSiteKey() string {
	if s.captcha == nil {
		return ""
	}
	return s.captcha.GetSiteKey()
}

// ==================== 内部方法 ====================

func (s *Service) createCaptchaChallenge(ctx context.Context, req *CreateRequest) (*CreateResponse, error) {
	challenge := types.NewChallenge(types.ChallengeTypeCaptcha, DefaultCaptchaTTL)
	challenge.FlowID = req.FlowID
	challenge.UserID = req.UserID

	if err := s.cache.SaveChallenge(ctx, challenge); err != nil {
		return nil, fmt.Errorf("save challenge: %w", err)
	}

	return &CreateResponse{
		ChallengeID: challenge.ID,
		Type:        string(challenge.Type),
		ExpiresIn:   int(time.Until(challenge.ExpiresAt).Seconds()),
		Data: map[string]any{
			"site_key": s.captcha.GetSiteKey(),
		},
	}, nil
}

func (s *Service) createTOTPChallenge(ctx context.Context, req *CreateRequest) (*CreateResponse, error) {
	if req.UserID == "" {
		return nil, fmt.Errorf("user_id is required for totp challenge")
	}

	challenge := types.NewChallenge(types.ChallengeTypeTOTP, DefaultTOTPTTL)
	challenge.FlowID = req.FlowID
	challenge.UserID = req.UserID

	if err := s.cache.SaveChallenge(ctx, challenge); err != nil {
		return nil, fmt.Errorf("save challenge: %w", err)
	}

	return &CreateResponse{
		ChallengeID: challenge.ID,
		Type:        string(challenge.Type),
		ExpiresIn:   int(time.Until(challenge.ExpiresAt).Seconds()),
	}, nil
}

func (s *Service) createEmailChallenge(ctx context.Context, req *CreateRequest) (*CreateResponse, error) {
	if req.Email == "" {
		return nil, fmt.Errorf("email is required for email challenge")
	}

	// 生成验证码
	code := generateOTP(DefaultOTPLength)

	// 创建 Challenge
	challenge := types.NewChallenge(types.ChallengeTypeEmail, DefaultEmailTTL)
	challenge.FlowID = req.FlowID
	challenge.UserID = req.UserID
	challenge.SetData("email", req.Email)
	challenge.SetData("masked_email", maskEmail(req.Email))

	// 保存验证码
	otpKey := "email:" + challenge.ID
	if err := s.cache.SaveOTP(ctx, otpKey, code); err != nil {
		return nil, fmt.Errorf("save otp: %w", err)
	}

	// 保存 Challenge
	if err := s.cache.SaveChallenge(ctx, challenge); err != nil {
		return nil, fmt.Errorf("save challenge: %w", err)
	}

	// 发送邮件
	if s.emailSender != nil {
		if err := s.emailSender.SendCode(ctx, req.Email, code); err != nil {
			logger.Errorf("[Challenge] 发送邮件失败: %v", err)
			return nil, fmt.Errorf("send email failed")
		}
	}

	logger.Infof("[Challenge] 创建 email challenge: %s, email: %s", challenge.ID, maskEmail(req.Email))

	return &CreateResponse{
		ChallengeID: challenge.ID,
		Type:        string(challenge.Type),
		ExpiresIn:   int(time.Until(challenge.ExpiresAt).Seconds()),
		Data: map[string]any{
			"masked_email": maskEmail(req.Email),
		},
	}, nil
}

func (s *Service) verifyCaptcha(ctx context.Context, challenge *types.Challenge, req *VerifyRequest, remoteIP string) (bool, error) {
	if req.Token == "" {
		return false, fmt.Errorf("token is required")
	}

	if s.captcha == nil {
		return false, fmt.Errorf("captcha verifier not configured")
	}

	return s.captcha.Verify(ctx, req.Token, remoteIP)
}

func (s *Service) verifyTOTP(_ context.Context, challenge *types.Challenge, req *VerifyRequest) (bool, error) {
	if req.Code == "" {
		return false, fmt.Errorf("code is required")
	}

	if s.totpVerifier == nil {
		return false, fmt.Errorf("totp verifier not configured")
	}

	return s.totpVerifier.Verify(context.Background(), challenge.UserID, req.Code)
}

func (s *Service) verifyEmail(ctx context.Context, challenge *types.Challenge, req *VerifyRequest) (bool, error) {
	if req.Code == "" {
		return false, fmt.Errorf("code is required")
	}

	otpKey := "email:" + challenge.ID
	storedCode, err := s.cache.GetOTP(ctx, otpKey)
	if err != nil {
		return false, fmt.Errorf("otp not found or expired")
	}

	if storedCode != req.Code {
		return false, fmt.Errorf("invalid code")
	}

	// 验证成功，删除 OTP
	_ = s.cache.DeleteOTP(ctx, otpKey)

	return true, nil
}

// ==================== 辅助函数 ====================

// generateOTP 生成数字验证码
func generateOTP(length int) string {
	const digits = "0123456789"
	result := make([]byte, length)
	for i := range result {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(digits))))
		result[i] = digits[n.Int64()]
	}
	return string(result)
}

// maskEmail 邮箱脱敏
func maskEmail(email string) string {
	if email == "" {
		return ""
	}
	at := -1
	for i, c := range email {
		if c == '@' {
			at = i
			break
		}
	}
	if at <= 0 {
		return email
	}
	if at <= 2 {
		return email[:1] + "**" + email[at:]
	}
	return email[:1] + "**" + email[at:]
}

// ==================== 错误类型 ====================

// CaptchaRequiredError 需要 Captcha 的错误
type CaptchaRequiredError struct {
	SiteKey string
}

func (e *CaptchaRequiredError) Error() string {
	return "captcha_required"
}

// IsCaptchaRequired 检查是否是 CaptchaRequired 错误
func IsCaptchaRequired(err error) (*CaptchaRequiredError, bool) {
	if e, ok := err.(*CaptchaRequiredError); ok {
		return e, true
	}
	return nil, false
}
