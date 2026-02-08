package challenge

import (
	"context"
	"time"

	"github.com/heliannuuthus/helios/internal/aegis/authenticator/captcha"
	"github.com/heliannuuthus/helios/internal/aegis/authenticator/mfa"
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
)

// Service Challenge 服务
type Service struct {
	cache     *cache.Manager
	captcha   captcha.Verifier
	providers map[types.ChallengeType]mfa.Provider
}

// NewService 创建 Challenge 服务
func NewService(cache *cache.Manager, captchaVerifier captcha.Verifier, providers []mfa.Provider) *Service {
	s := &Service{
		cache:     cache,
		captcha:   captchaVerifier,
		providers: make(map[types.ChallengeType]mfa.Provider),
	}
	for _, p := range providers {
		s.providers[types.ChallengeType(p.Type())] = p
	}
	return s
}

// ==================== Create ====================

// Create 创建 Challenge
func (s *Service) Create(ctx context.Context, req *CreateRequest, remoteIP string) (*CreateResponse, error) {
	// 检查是否需要 captcha 前置验证
	if req.Type.RequiresCaptcha() && s.captcha != nil {
		if req.CaptchaToken == "" {
			return s.createChallengeWithCaptchaRequired(ctx, req)
		}

		ok, err := s.captcha.Verify(ctx, req.CaptchaToken, remoteIP)
		if err != nil || !ok {
			logger.Warnf("[Challenge] captcha 验证失败: %v", err)
			return nil, autherrors.NewInvalidRequest("captcha verification failed")
		}
	}

	// 根据类型创建 Challenge
	switch req.Type {
	case types.ChallengeTypeCaptcha:
		return s.createCaptchaChallenge(ctx)
	case types.ChallengeTypeTOTP:
		return s.createTOTPChallenge(ctx, req)
	case types.ChallengeTypeEmailOTP:
		return s.createEmailOTPChallenge(ctx, req)
	default:
		return nil, autherrors.NewInvalidRequestf("unsupported challenge type: %s", req.Type)
	}
}

func (s *Service) createCaptchaChallenge(ctx context.Context) (*CreateResponse, error) {
	challenge := types.NewChallenge(types.ChallengeTypeCaptcha, DefaultCaptchaTTL)

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
	challenge.SetData("user_id", req.UserID)

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

	challenge := types.NewChallenge(types.ChallengeTypeEmailOTP, DefaultEmailTTL)
	challenge.SetData("email", req.Email)
	challenge.SetData("masked_email", helperutil.MaskEmail(req.Email))

	// 委托 provider 发送验证码
	if err := s.sendOTP(ctx, challenge); err != nil {
		return nil, err
	}

	if err := s.cache.SaveChallenge(ctx, challenge); err != nil {
		return nil, autherrors.NewServerErrorf("save challenge: %v", err)
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

// createChallengeWithCaptchaRequired 创建需要 captcha 前置的 challenge
func (s *Service) createChallengeWithCaptchaRequired(ctx context.Context, req *CreateRequest) (*CreateResponse, error) {
	var challenge *types.Challenge
	switch req.Type {
	case types.ChallengeTypeEmailOTP:
		if req.Email == "" {
			return nil, autherrors.NewInvalidRequest("email is required for email-otp challenge")
		}
		challenge = types.NewChallenge(types.ChallengeTypeEmailOTP, DefaultEmailTTL)
		challenge.SetData("email", req.Email)
		challenge.SetData("masked_email", helperutil.MaskEmail(req.Email))
		challenge.SetData("pending_captcha", true)
	case types.ChallengeTypeTOTP:
		if req.UserID == "" {
			return nil, autherrors.NewInvalidRequest("user_id is required for totp challenge")
		}
		challenge = types.NewChallenge(types.ChallengeTypeTOTP, DefaultTOTPTTL)
		challenge.SetData("user_id", req.UserID)
		challenge.SetData("pending_captcha", true)
	default:
		return nil, autherrors.NewInvalidRequestf("unsupported challenge type for captcha: %s", req.Type)
	}

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

// ==================== Verify ====================

// Verify 验证 Challenge
func (s *Service) Verify(ctx context.Context, challengeID string, req *VerifyRequest, remoteIP string) (*VerifyResponse, error) {
	if req.Proof == nil {
		return nil, autherrors.NewInvalidRequest("proof is required")
	}

	challenge, err := s.cache.GetChallenge(ctx, challengeID)
	if err != nil {
		return nil, autherrors.NewNotFound("challenge not found")
	}

	if challenge.IsExpired() {
		return nil, autherrors.NewInvalidRequest("challenge expired")
	}

	// pending_captcha 状态：先验证 captcha，通过后触发实际初始化（如发送邮件）
	if pending, _ := challenge.GetData("pending_captcha"); pending == true {
		if _, err := s.verifyCaptcha(ctx, req, remoteIP); err != nil {
			return nil, err
		}
		delete(challenge.Data, "pending_captcha")
		return s.continueAfterCaptcha(ctx, challenge)
	}

	// 根据类型验证
	var verified bool
	switch challenge.Type {
	case types.ChallengeTypeCaptcha:
		verified, err = s.verifyCaptcha(ctx, req, remoteIP)
	default:
		// 委托给 mfa.Provider
		verified, err = s.verifyWithProvider(ctx, challenge, req)
	}

	if err != nil {
		return nil, err
	}

	if verified {
		if err := s.cache.DeleteChallenge(ctx, challenge.ID); err != nil {
			logger.Warnf("[Challenge] 删除 challenge 失败: %v", err)
		}
	}

	return &VerifyResponse{Verified: verified}, nil
}

// verifyCaptcha 验证 captcha（captcha 不走 mfa.Provider，有自己的接口）
func (s *Service) verifyCaptcha(ctx context.Context, req *VerifyRequest, remoteIP string) (bool, error) {
	proof, err := stringProof(req.Proof)
	if err != nil {
		return false, err
	}

	if s.captcha == nil {
		return false, autherrors.NewServerError("captcha verifier not configured")
	}

	return s.captcha.Verify(ctx, proof, remoteIP)
}

// verifyWithProvider 委托给注册的 mfa.Provider 执行验证
func (s *Service) verifyWithProvider(ctx context.Context, challenge *types.Challenge, req *VerifyRequest) (bool, error) {
	p, ok := s.providers[challenge.Type]
	if !ok {
		return false, autherrors.NewInvalidRequestf("unsupported challenge type: %s", challenge.Type)
	}

	proof, err := stringProof(req.Proof)
	if err != nil {
		return false, err
	}

	// 根据类型传递额外参数
	switch challenge.Type {
	case types.ChallengeTypeTOTP:
		userID := challenge.GetStringData("user_id")
		if userID == "" {
			return false, autherrors.NewInvalidRequest("user_id not found in challenge")
		}
		return p.Verify(ctx, proof, userID)
	case types.ChallengeTypeEmailOTP:
		return p.Verify(ctx, proof, challenge.ID)
	default:
		return p.Verify(ctx, proof)
	}
}

// continueAfterCaptcha captcha 前置验证通过后，执行 challenge 的实际初始化
func (s *Service) continueAfterCaptcha(ctx context.Context, challenge *types.Challenge) (*VerifyResponse, error) {
	switch challenge.Type {
	case types.ChallengeTypeEmailOTP:
		if err := s.sendOTP(ctx, challenge); err != nil {
			return nil, err
		}
	default:
		// TOTP 等类型不需要额外操作
	}

	if err := s.cache.SaveChallenge(ctx, challenge); err != nil {
		logger.Warnf("[Challenge] 保存 challenge 失败: %v", err)
	}

	return &VerifyResponse{
		ChallengeID: challenge.ID,
		Data: map[string]any{
			"next": string(challenge.Type),
		},
	}, nil
}

// sendOTP 委托 EmailOTPProvider 发送验证码
func (s *Service) sendOTP(ctx context.Context, challenge *types.Challenge) error {
	p, ok := s.providers[challenge.Type]
	if !ok {
		return autherrors.NewInvalidRequestf("no provider for challenge type: %s", challenge.Type)
	}

	// EmailOTPProvider 实现了 SendOTP 方法
	sender, ok := p.(interface {
		SendOTP(ctx context.Context, email, challengeID string) error
	})
	if !ok {
		return nil // 该类型不需要发送操作
	}

	email := challenge.GetStringData("email")
	if email == "" {
		return autherrors.NewInvalidRequest("email not found in challenge")
	}

	return sender.SendOTP(ctx, email, challenge.ID)
}

// ==================== 查询方法 ====================

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

// ==================== 辅助函数 ====================

// stringProof 从 Proof 中提取 string 类型的证明
func stringProof(proof any) (string, error) {
	s, ok := proof.(string)
	if !ok {
		return "", autherrors.NewInvalidRequest("proof must be a string")
	}
	if s == "" {
		return "", autherrors.NewInvalidRequest("proof must not be empty")
	}
	return s, nil
}
