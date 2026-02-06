package challenge

import (
	"context"
	"time"

	"github.com/heliannuuthus/helios/internal/aegis/authenticator"
	"github.com/heliannuuthus/helios/internal/aegis/authenticator/captcha"
	"github.com/heliannuuthus/helios/internal/aegis/cache"
	autherrors "github.com/heliannuuthus/helios/internal/aegis/errors"
	"github.com/heliannuuthus/helios/internal/aegis/types"
	"github.com/heliannuuthus/helios/pkg/helperutil"
	"github.com/heliannuuthus/helios/pkg/logger"
)

// 默认过期时间
const (
	DefaultCaptchaTTL = 5 * time.Minute
	DefaultTOTPTTL    = 5 * time.Minute
	DefaultEmailTTL   = 5 * time.Minute
	DefaultOTPLength  = 6
)

// EmailSender 邮件发送接口
type EmailSender interface {
	SendCode(ctx context.Context, email, code string) error
}

// Service Challenge 服务
type Service struct {
	cache        *cache.Manager
	captcha      captcha.Verifier
	emailSender  EmailSender
	totpVerifier authenticator.TOTPVerifier
}

// ServiceConfig 服务配置
type ServiceConfig struct {
	Cache        *cache.Manager
	Captcha      captcha.Verifier
	EmailSender  EmailSender
	TOTPVerifier authenticator.TOTPVerifier
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
	if req.Type.RequiresCaptcha() && s.captcha != nil {
		if req.CaptchaToken == "" {
			// 需要 captcha 但未提供 token，先创建目标 challenge，返回 required
			return s.createChallengeWithCaptchaRequired(ctx, req)
		}

		// 验证 captcha token
		ok, err := s.captcha.Verify(ctx, req.CaptchaToken, remoteIP)
		if err != nil || !ok {
			logger.Warnf("[Challenge] captcha 验证失败: %v", err)
			return nil, autherrors.NewInvalidRequest("captcha verification failed")
		}
	}

	// 根据类型创建 Challenge（captcha 已验证或不需要）
	switch req.Type {
	case types.ChallengeTypeCaptcha:
		return s.createCaptchaChallenge(ctx, req)
	case types.ChallengeTypeTOTP:
		return s.createTOTPChallenge(ctx, req)
	case types.ChallengeTypeEmailOTP:
		return s.createEmailOTPChallenge(ctx, req)
	default:
		return nil, autherrors.NewInvalidRequestf("unsupported challenge type: %s", req.Type)
	}
}

// createChallengeWithCaptchaRequired 创建需要 captcha 前置的 challenge
// 返回 challenge_id 和 required 配置，前端需要先完成 captcha 验证
func (s *Service) createChallengeWithCaptchaRequired(ctx context.Context, req *CreateRequest) (*CreateResponse, error) {
	// 先创建目标 challenge（状态为 pending_captcha）
	var challenge *types.Challenge
	switch req.Type {
	case types.ChallengeTypeEmailOTP:
		if req.Email == "" {
			return nil, autherrors.NewInvalidRequest("email is required for email-otp challenge")
		}
		challenge = types.NewChallenge(types.ChallengeTypeEmailOTP, DefaultEmailTTL)
		challenge.SetData("email", req.Email)
		challenge.SetData("masked_email", helperutil.MaskEmail(req.Email))
		challenge.SetData("pending_captcha", true) // 标记需要先验证 captcha
	case types.ChallengeTypeTOTP:
		if req.UserID == "" {
			return nil, autherrors.NewInvalidRequest("user_id is required for totp challenge")
		}
		challenge = types.NewChallenge(types.ChallengeTypeTOTP, DefaultTOTPTTL)
		challenge.SetData("pending_captcha", true)
	default:
		return nil, autherrors.NewInvalidRequestf("unsupported challenge type for captcha: %s", req.Type)
	}

	challenge.FlowID = req.FlowID
	challenge.UserID = req.UserID

	// 保存 challenge
	if err := s.cache.SaveChallenge(ctx, challenge); err != nil {
		return nil, autherrors.NewServerErrorf("save challenge: %v", err)
	}

	logger.Infof("[Challenge] 创建 pending challenge: %s, type: %s, 需要 captcha 前置验证", challenge.ID, challenge.Type)

	return &CreateResponse{
		ChallengeID: challenge.ID,
		Required: &types.VChanConfig{
			Connection: "captcha:" + s.captcha.GetProvider(),
			Identifier: s.captcha.GetIdentifier(),
		},
	}, nil
}

// Verify 验证 Challenge
func (s *Service) Verify(ctx context.Context, challengeID string, req *VerifyRequest, remoteIP string) (*VerifyResponse, error) {
	// 获取 Challenge
	challenge, err := s.cache.GetChallenge(ctx, challengeID)
	if err != nil {
		return nil, autherrors.NewNotFound("challenge not found")
	}

	// 检查是否已过期
	if challenge.IsExpired() {
		return nil, autherrors.NewInvalidRequest("challenge expired")
	}

	// 检查是否已验证
	if challenge.Verified {
		return &VerifyResponse{Verified: true}, nil
	}

	// 检查是否是 pending_captcha 状态（需要先验证 captcha）
	if pending, _ := challenge.GetData("pending_captcha"); pending == true {
		return s.verifyCaptchaAndContinue(ctx, challenge, req, remoteIP)
	}

	// 根据类型验证
	var verified bool
	switch challenge.Type {
	case types.ChallengeTypeCaptcha:
		verified, err = s.verifyCaptcha(ctx, challenge, req, remoteIP)
	case types.ChallengeTypeTOTP:
		verified, err = s.verifyTOTP(ctx, challenge, req)
	case types.ChallengeTypeEmailOTP:
		verified, err = s.verifyEmailOTP(ctx, challenge, req)
	default:
		return nil, autherrors.NewInvalidRequestf("unsupported challenge type: %s", challenge.Type)
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

// verifyCaptchaAndContinue 验证 captcha 并继续执行后续操作
func (s *Service) verifyCaptchaAndContinue(ctx context.Context, challenge *types.Challenge, req *VerifyRequest, remoteIP string) (*VerifyResponse, error) {
	// 验证 captcha proof
	if req.Proof == "" {
		return nil, autherrors.NewInvalidRequest("proof is required")
	}

	ok, err := s.captcha.Verify(ctx, req.Proof, remoteIP)
	if err != nil || !ok {
		logger.Warnf("[Challenge] captcha 验证失败: %v", err)
		return nil, autherrors.NewInvalidRequest("captcha verification failed")
	}

	// captcha 验证通过，移除 pending 标记
	delete(challenge.Data, "pending_captcha")

	// 根据 challenge 类型执行后续操作
	switch challenge.Type {
	case types.ChallengeTypeEmailOTP:
		// 发送邮件验证码
		email := challenge.GetStringData("email")
		if email == "" {
			return nil, autherrors.NewInvalidRequest("email not found in challenge")
		}

		code, err := helperutil.GenerateOTP(DefaultOTPLength)
		if err != nil {
			return nil, autherrors.NewServerErrorf("generate otp: %v", err)
		}
		otpKey := "email-otp:" + challenge.ID
		if err := s.cache.SaveOTP(ctx, otpKey, code); err != nil {
			return nil, autherrors.NewServerErrorf("save otp: %v", err)
		}

		// 发送邮件
		if s.emailSender != nil {
			if err := s.emailSender.SendCode(ctx, email, code); err != nil {
				logger.Errorf("[Challenge] 发送邮件失败: %v", err)
				return nil, autherrors.NewServerError("send email failed")
			}
		}

		// 保存更新后的 challenge
		if err := s.cache.SaveChallenge(ctx, challenge); err != nil {
			logger.Warnf("[Challenge] 保存 challenge 失败: %v", err)
		}

		logger.Infof("[Challenge] captcha 验证通过，已发送邮件: %s", helperutil.MaskEmail(email))

		return &VerifyResponse{
			Verified:    true, // captcha 验证通过
			ChallengeID: challenge.ID,
			Data: map[string]any{
				"masked_email": helperutil.MaskEmail(email),
				"next":         "email-otp", // 提示前端下一步
			},
		}, nil

	case types.ChallengeTypeTOTP:
		// TOTP 不需要额外操作，直接返回
		if err := s.cache.SaveChallenge(ctx, challenge); err != nil {
			logger.Warnf("[Challenge] 保存 challenge 失败: %v", err)
		}

		return &VerifyResponse{
			Verified:    true,
			ChallengeID: challenge.ID,
			Data: map[string]any{
				"next": "verify_totp",
			},
		}, nil

	default:
		return nil, autherrors.NewInvalidRequestf("unsupported challenge type: %s", challenge.Type)
	}
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
	return s.captcha.GetIdentifier()
}

// ==================== 内部方法 ====================

func (s *Service) createCaptchaChallenge(ctx context.Context, req *CreateRequest) (*CreateResponse, error) {
	challenge := types.NewChallenge(types.ChallengeTypeCaptcha, DefaultCaptchaTTL)
	challenge.FlowID = req.FlowID
	challenge.UserID = req.UserID

	if err := s.cache.SaveChallenge(ctx, challenge); err != nil {
		return nil, autherrors.NewServerErrorf("save challenge: %v", err)
	}

	return &CreateResponse{
		ChallengeID: challenge.ID,
		Type:        string(challenge.Type),
		ExpiresIn:   int(time.Until(challenge.ExpiresAt).Seconds()),
		Data: map[string]any{
			"site_key": s.captcha.GetIdentifier(),
		},
	}, nil
}

func (s *Service) createTOTPChallenge(ctx context.Context, req *CreateRequest) (*CreateResponse, error) {
	if req.UserID == "" {
		return nil, autherrors.NewInvalidRequest("user_id is required for totp challenge")
	}

	challenge := types.NewChallenge(types.ChallengeTypeTOTP, DefaultTOTPTTL)
	challenge.FlowID = req.FlowID
	challenge.UserID = req.UserID

	if err := s.cache.SaveChallenge(ctx, challenge); err != nil {
		return nil, autherrors.NewServerErrorf("save challenge: %v", err)
	}

	return &CreateResponse{
		ChallengeID: challenge.ID,
		Type:        string(challenge.Type),
		ExpiresIn:   int(time.Until(challenge.ExpiresAt).Seconds()),
	}, nil
}

func (s *Service) createEmailOTPChallenge(ctx context.Context, req *CreateRequest) (*CreateResponse, error) {
	if req.Email == "" {
		return nil, autherrors.NewInvalidRequest("email is required for email-otp challenge")
	}

	// 生成验证码
	code, err := helperutil.GenerateOTP(DefaultOTPLength)
	if err != nil {
		return nil, autherrors.NewServerErrorf("generate otp: %v", err)
	}

	// 创建 Challenge
	challenge := types.NewChallenge(types.ChallengeTypeEmailOTP, DefaultEmailTTL)
	challenge.FlowID = req.FlowID
	challenge.UserID = req.UserID
	challenge.SetData("email", req.Email)
	challenge.SetData("masked_email", helperutil.MaskEmail(req.Email))

	// 保存验证码
	otpKey := "email-otp:" + challenge.ID
	if err := s.cache.SaveOTP(ctx, otpKey, code); err != nil {
		return nil, autherrors.NewServerErrorf("save otp: %v", err)
	}

	// 保存 Challenge
	if err := s.cache.SaveChallenge(ctx, challenge); err != nil {
		return nil, autherrors.NewServerErrorf("save challenge: %v", err)
	}

	// 发送邮件
	if s.emailSender != nil {
		if err := s.emailSender.SendCode(ctx, req.Email, code); err != nil {
			logger.Errorf("[Challenge] 发送邮件失败: %v", err)
			return nil, autherrors.NewServerError("send email failed")
		}
	}

	logger.Infof("[Challenge] 创建 email-otp challenge: %s, email: %s", challenge.ID, helperutil.MaskEmail(req.Email))

	return &CreateResponse{
		ChallengeID: challenge.ID,
		Type:        string(challenge.Type),
		ExpiresIn:   int(time.Until(challenge.ExpiresAt).Seconds()),
		Data: map[string]any{
			"masked_email": helperutil.MaskEmail(req.Email),
		},
	}, nil
}

func (s *Service) verifyCaptcha(ctx context.Context, _ *types.Challenge, req *VerifyRequest, remoteIP string) (bool, error) {
	if req.Proof == "" {
		return false, autherrors.NewInvalidRequest("proof is required")
	}

	if s.captcha == nil {
		return false, autherrors.NewServerError("captcha verifier not configured")
	}

	return s.captcha.Verify(ctx, req.Proof, remoteIP)
}

func (s *Service) verifyTOTP(ctx context.Context, challenge *types.Challenge, req *VerifyRequest) (bool, error) {
	if req.Proof == "" {
		return false, autherrors.NewInvalidRequest("proof is required")
	}

	if s.totpVerifier == nil {
		return false, autherrors.NewServerError("totp verifier not configured")
	}

	return s.totpVerifier.Verify(ctx, challenge.UserID, req.Proof)
}

func (s *Service) verifyEmailOTP(ctx context.Context, challenge *types.Challenge, req *VerifyRequest) (bool, error) {
	if req.Proof == "" {
		return false, autherrors.NewInvalidRequest("proof is required")
	}

	otpKey := "email-otp:" + challenge.ID
	storedCode, err := s.cache.GetOTP(ctx, otpKey)
	if err != nil {
		return false, autherrors.NewInvalidRequest("otp not found or expired")
	}

	if storedCode != req.Proof {
		return false, autherrors.NewInvalidRequest("invalid code")
	}

	// 验证成功，删除 OTP（忽略删除失败，OTP 会在过期后自动清理）
	_ = s.cache.DeleteOTP(ctx, otpKey) //nolint:errcheck

	return true, nil
}
