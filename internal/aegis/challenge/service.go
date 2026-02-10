package challenge

import (
	"context"
	"time"

	"github.com/heliannuuthus/helios/internal/aegis/authenticate"
	"github.com/heliannuuthus/helios/internal/aegis/authenticator"
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

// otpSender 能够发送 OTP 的接口
type otpSender interface {
	SendOTP(ctx context.Context, email, challengeID string) error
}

// Service Challenge 服务
type Service struct {
	cache    *cache.Manager
	registry *authenticator.Registry
}

// NewService 创建 Challenge 服务
func NewService(cache *cache.Manager, registry *authenticator.Registry) *Service {
	return &Service{
		cache:    cache,
		registry: registry,
	}
}

// ==================== 内部查询 ====================

// getCaptchaVerifier 从 Registry 获取 captcha.Verifier
func (s *Service) getCaptchaVerifier() captcha.Verifier {
	a, ok := s.registry.Get(types.ConnCaptcha)
	if !ok {
		return nil
	}
	vchan, ok := a.(*authenticate.VChanAuthenticator)
	if !ok {
		return nil
	}
	return vchan.Verifier()
}

// getCaptchaConfig 从 Registry 获取 captcha 的 ConnectionConfig
func (s *Service) getCaptchaConfig() *types.ConnectionConfig {
	a, ok := s.registry.Get(types.ConnCaptcha)
	if !ok {
		return nil
	}
	return a.Prepare()
}

// getMFAProvider 从 Registry 获取指定类型的 mfa.Provider
func (s *Service) getMFAProvider(connection string) mfa.Provider {
	a, ok := s.registry.Get(connection)
	if !ok {
		return nil
	}
	mfaAuth, ok := a.(*authenticate.MFAAuthenticator)
	if !ok {
		return nil
	}
	return mfaAuth.Provider()
}

// ==================== Create ====================

// Create 创建 Challenge
// 始终创建 challenge 并返回 challenge_id。
// 如果该类型需要 captcha 前置 → 标记 pending_captcha，附带 required 配置，不触发副作用。
// 不需要 captcha → 直接触发副作用（如发送邮件）。
func (s *Service) Create(ctx context.Context, req *CreateRequest, remoteIP string) (*CreateResponse, error) {
	challenge, err := s.buildChallenge(req)
	if err != nil {
		return nil, err
	}

	// 需要 captcha 前置
	if req.Type.RequiresCaptcha() && s.getCaptchaVerifier() != nil {
		challenge.SetData(types.ChallengeDataPendingCaptcha, true)

		if err := s.cache.SaveChallenge(ctx, challenge); err != nil {
			return nil, autherrors.NewServerErrorf("save challenge: %v", err)
		}

		return &CreateResponse{
			ChallengeID: challenge.ID,
			Required:    s.getCaptchaConfig(),
		}, nil
	}

	// 不需要 captcha，直接执行副作用
	if err := s.executeSideEffects(ctx, challenge); err != nil {
		return nil, err
	}

	if err := s.cache.SaveChallenge(ctx, challenge); err != nil {
		return nil, autherrors.NewServerErrorf("save challenge: %v", err)
	}

	return s.buildCreateResponse(challenge), nil
}

// buildChallenge 根据请求构建 Challenge 对象（不持久化）
func (s *Service) buildChallenge(req *CreateRequest) (*types.Challenge, error) {
	switch req.Type {
	case types.ChallengeTypeCaptcha:
		if s.getCaptchaVerifier() == nil {
			return nil, autherrors.NewServerError("captcha verifier not configured")
		}
		return types.NewChallenge(types.ChallengeTypeCaptcha, DefaultCaptchaTTL), nil

	case types.ChallengeTypeTOTP:
		if req.UserID == "" {
			return nil, autherrors.NewInvalidRequest("user_id is required for totp challenge")
		}
		c := types.NewChallenge(types.ChallengeTypeTOTP, DefaultTOTPTTL)
		c.SetData(types.ChallengeDataUserID, req.UserID)
		return c, nil

	case types.ChallengeTypeEmailOTP:
		if req.Email == "" {
			return nil, autherrors.NewInvalidRequest("email is required for email_otp challenge")
		}
		c := types.NewChallenge(types.ChallengeTypeEmailOTP, DefaultEmailTTL)
		c.SetData(types.ChallengeDataEmail, req.Email)
		c.SetData(types.ChallengeDataMaskedEmail, helperutil.MaskEmail(req.Email))
		return c, nil

	default:
		return nil, autherrors.NewInvalidRequestf("unsupported challenge type: %s", req.Type)
	}
}

// buildCreateResponse 构建创建响应（challenge 已就绪，无 pending）
func (s *Service) buildCreateResponse(challenge *types.Challenge) *CreateResponse {
	resp := &CreateResponse{
		ChallengeID: challenge.ID,
		Type:        string(challenge.Type),
		ExpiresIn:   int(time.Until(challenge.ExpiresAt).Seconds()),
	}

	switch challenge.Type {
	case types.ChallengeTypeCaptcha:
		if verifier := s.getCaptchaVerifier(); verifier != nil {
			resp.Data = map[string]any{
				types.ChallengeDataSiteKey: verifier.GetIdentifier(),
			}
		}
	case types.ChallengeTypeEmailOTP:
		maskedEmail := challenge.GetStringData(types.ChallengeDataMaskedEmail)
		if maskedEmail != "" {
			resp.Data = map[string]any{
				types.ChallengeDataMaskedEmail: maskedEmail,
			}
		}
	}

	return resp
}

// executeSideEffects 执行 challenge 创建后的副作用（如发送邮件）
func (s *Service) executeSideEffects(ctx context.Context, challenge *types.Challenge) error {
	if challenge.Type == types.ChallengeTypeEmailOTP {
		return s.sendOTP(ctx, challenge)
	}
	return nil
}

// ==================== Verify ====================

// Verify 验证 Challenge
// 前端通过 connection 显式指定本次提交的验证类型：
//   - connection = "captcha" 且 challenge 处于 pending_captcha → 验证 captcha，通过后触发副作用
//   - connection = challenge.Type → 验证实际 proof
func (s *Service) Verify(ctx context.Context, challengeID string, req *VerifyRequest, remoteIP string) (*VerifyResponse, error) {
	challenge, err := s.cache.GetChallenge(ctx, challengeID)
	if err != nil {
		return nil, autherrors.NewNotFound("challenge not found")
	}

	if challenge.IsExpired() {
		return nil, autherrors.NewInvalidRequest("challenge expired")
	}

	switch req.Connection {
	case types.ConnCaptcha:
		return s.handleCaptchaVerify(ctx, challenge, req, remoteIP)
	case string(challenge.Type):
		return s.handleChallengeVerify(ctx, challenge, req)
	default:
		return nil, autherrors.NewInvalidRequestf("connection %q does not match challenge type %q", req.Connection, challenge.Type)
	}
}

// handleCaptchaVerify 处理 captcha 验证（前置条件验证）
func (s *Service) handleCaptchaVerify(ctx context.Context, challenge *types.Challenge, req *VerifyRequest, remoteIP string) (*VerifyResponse, error) {
	// 如果 challenge 本身就是 captcha 类型，直接验证
	if challenge.Type == types.ChallengeTypeCaptcha {
		return s.handleChallengeVerify(ctx, challenge, req)
	}

	// 否则必须处于 pending_captcha 状态
	pending, _ := challenge.GetData(types.ChallengeDataPendingCaptcha)
	if pending != true {
		return nil, autherrors.NewInvalidRequest("challenge does not require captcha verification")
	}

	// 验证 captcha
	proof, err := stringProof(req.Proof)
	if err != nil {
		return nil, err
	}

	verifier := s.getCaptchaVerifier()
	if verifier == nil {
		return nil, autherrors.NewServerError("captcha verifier not configured")
	}

	ok, err := verifier.Verify(ctx, proof, remoteIP)
	if err != nil || !ok {
		logger.Warnf("[Challenge] captcha 验证失败: %v", err)
		return nil, autherrors.NewInvalidRequest("captcha verification failed")
	}

	// captcha 通过，清除 pending 标记，执行副作用
	delete(challenge.Data, types.ChallengeDataPendingCaptcha)

	if err := s.executeSideEffects(ctx, challenge); err != nil {
		return nil, err
	}

	if err := s.cache.SaveChallenge(ctx, challenge); err != nil {
		return nil, autherrors.NewServerErrorf("save challenge: %v", err)
	}

	return &VerifyResponse{
		ChallengeID: challenge.ID,
		Data: map[string]any{
			types.ChallengeDataNext: string(challenge.Type),
		},
	}, nil
}

// handleChallengeVerify 处理实际的 challenge 验证
func (s *Service) handleChallengeVerify(ctx context.Context, challenge *types.Challenge, req *VerifyRequest) (*VerifyResponse, error) {
	// 如果还有 pending 前置条件未完成，不允许直接验证
	if pending, _ := challenge.GetData(types.ChallengeDataPendingCaptcha); pending == true {
		return nil, autherrors.NewInvalidRequest("captcha verification required before challenge verification")
	}

	proof, err := stringProof(req.Proof)
	if err != nil {
		return nil, err
	}

	var verified bool
	switch challenge.Type {
	case types.ChallengeTypeCaptcha:
		verifier := s.getCaptchaVerifier()
		if verifier == nil {
			return nil, autherrors.NewServerError("captcha verifier not configured")
		}
		// captcha 类型没有 remoteIP（已在 handler 层传入）—— 这里走 provider 验证
		// 注意：纯 captcha challenge 的 remoteIP 通过 handleCaptchaVerify 处理
		verified, err = verifier.Verify(ctx, proof, "")
	default:
		verified, err = s.verifyWithProvider(ctx, challenge, proof)
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

// verifyWithProvider 委托给注册的 mfa.Provider 执行验证
func (s *Service) verifyWithProvider(ctx context.Context, challenge *types.Challenge, proof string) (bool, error) {
	p := s.getMFAProvider(string(challenge.Type))
	if p == nil {
		return false, autherrors.NewInvalidRequestf("unsupported challenge type: %s", challenge.Type)
	}

	switch challenge.Type {
	case types.ChallengeTypeTOTP:
		userID := challenge.GetStringData(types.ChallengeDataUserID)
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

// sendOTP 委托 Provider 发送验证码
func (s *Service) sendOTP(ctx context.Context, challenge *types.Challenge) error {
	p := s.getMFAProvider(string(challenge.Type))
	if p == nil {
		return autherrors.NewInvalidRequestf("no provider for challenge type: %s", challenge.Type)
	}

	sender, ok := p.(otpSender)
	if !ok {
		return nil // 该类型不需要发送操作
	}

	email := challenge.GetStringData(types.ChallengeDataEmail)
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
	verifier := s.getCaptchaVerifier()
	if verifier == nil {
		return ""
	}
	return verifier.GetIdentifier()
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
