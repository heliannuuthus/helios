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
	DefaultCaptchaTTL        = 5 * time.Minute
	DefaultTOTPTTL           = 5 * time.Minute
	DefaultEmailTTL          = 5 * time.Minute
	DefaultWebAuthnTTL       = 5 * time.Minute
	DefaultChallengeTokenTTL = 5 * time.Minute // ChallengeToken 有效期
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

// ==================== 校验 ====================

// validateClientAndAudience 校验 client_id 对应的应用存在，audience 服务存在且应用有权访问
func (s *Service) validateClientAndAudience(ctx context.Context, clientID, audience string) error {
	// 1. 校验应用存在
	_, err := s.cache.GetApplication(ctx, clientID)
	if err != nil {
		return autherrors.NewInvalidRequestf("invalid client_id: %s", clientID)
	}

	// 2. 校验服务存在
	_, err = s.cache.GetService(ctx, audience)
	if err != nil {
		return autherrors.NewInvalidRequestf("invalid audience: %s", audience)
	}

	// 3. 校验应用与服务的关联关系
	allowed, err := s.cache.CheckAppServiceRelation(ctx, clientID, audience)
	if err != nil {
		return autherrors.NewServerErrorf("check application-service relation: %v", err)
	}
	if !allowed {
		return autherrors.NewInvalidRequestf("application %s is not authorized to access service %s", clientID, audience)
	}
	return nil
}

// ==================== Create ====================

// Create 创建 Challenge
// 始终创建 challenge 并返回 challenge_id。
// 如果该 channel_type 需要 captcha 前置 → 标记 pending_captcha，附带 required 配置，不触发副作用。
// 不需要 captcha → 直接触发副作用（如发送邮件）。
func (s *Service) Create(ctx context.Context, req *CreateRequest, remoteIP string) (*CreateResponse, error) {
	// 校验 client_id 和 audience 合法性
	if err := s.validateClientAndAudience(ctx, req.ClientID, req.Audience); err != nil {
		return nil, err
	}

	challenge, err := s.buildChallenge(req)
	if err != nil {
		return nil, err
	}

	// 需要 captcha 前置
	if req.ChannelType.RequiresCaptcha() && s.getCaptchaVerifier() != nil {
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
	switch req.ChannelType {
	case types.ChannelTypeTOTP:
		if req.Channel == "" {
			return nil, autherrors.NewInvalidRequest("channel is required for totp (user_id)")
		}
		return types.NewChallenge(req.ClientID, req.Audience, req.Type, types.ChannelTypeTOTP, req.Channel, DefaultTOTPTTL), nil

	case types.ChannelTypeEmailOTP:
		if req.Channel == "" {
			return nil, autherrors.NewInvalidRequest("channel is required for email_otp (email address)")
		}
		c := types.NewChallenge(req.ClientID, req.Audience, req.Type, types.ChannelTypeEmailOTP, req.Channel, DefaultEmailTTL)
		c.SetData(types.ChallengeDataMaskedEmail, helperutil.MaskEmail(req.Channel))
		return c, nil

	case types.ChannelTypeWebAuthn:
		// WebAuthn channel 可空（discoverable login 不需要指定用户）
		return types.NewChallenge(req.ClientID, req.Audience, req.Type, types.ChannelTypeWebAuthn, req.Channel, DefaultWebAuthnTTL), nil

	case types.ChannelTypeWechatMP, types.ChannelTypeAlipayMP:
		// 交换类：channel 必填（平台 code）
		if req.Channel == "" {
			return nil, autherrors.NewInvalidRequestf("channel is required for %s (platform code)", req.ChannelType)
		}
		return types.NewChallenge(req.ClientID, req.Audience, "", req.ChannelType, req.Channel, DefaultCaptchaTTL), nil

	default:
		return nil, autherrors.NewInvalidRequestf("unsupported channel type: %s", req.ChannelType)
	}
}

// buildCreateResponse 构建创建响应（challenge 已就绪，无 pending）
func (s *Service) buildCreateResponse(challenge *types.Challenge) *CreateResponse {
	resp := &CreateResponse{
		ChallengeID: challenge.ID,
		ChannelType: string(challenge.ChannelType),
		ExpiresIn:   int(time.Until(challenge.ExpiresAt).Seconds()),
	}

	switch challenge.ChannelType {
	case types.ChannelTypeEmailOTP:
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
	if challenge.ChannelType == types.ChannelTypeEmailOTP {
		return s.sendOTP(ctx, challenge)
	}
	return nil
}

// ==================== Verify ====================

// Verify 验证 Challenge
// 前端通过 channel_type 显式指定本次提交的验证类型：
//   - channel_type = "captcha" 且 challenge 处于 pending_captcha → 验证 captcha，通过后触发副作用
//   - channel_type = challenge.ChannelType → 验证实际 proof
//
// 返回 VerifyResult（不含 Token），Token 由 handler 层负责签发
func (s *Service) Verify(ctx context.Context, challengeID string, req *VerifyRequest, remoteIP string) (*VerifyResult, error) {
	challenge, err := s.cache.GetChallenge(ctx, challengeID)
	if err != nil {
		return nil, autherrors.NewNotFound("challenge not found")
	}

	if challenge.IsExpired() {
		return nil, autherrors.NewInvalidRequest("challenge expired")
	}

	switch req.ChannelType {
	case types.ConnCaptcha:
		return s.handleCaptchaVerify(ctx, challenge, req, remoteIP)
	case string(challenge.ChannelType):
		return s.handleChallengeVerify(ctx, challenge, req)
	default:
		return nil, autherrors.NewInvalidRequestf("channel_type %q does not match challenge channel_type %q", req.ChannelType, challenge.ChannelType)
	}
}

// handleCaptchaVerify 处理 captcha 验证（前置条件验证）
func (s *Service) handleCaptchaVerify(ctx context.Context, challenge *types.Challenge, req *VerifyRequest, remoteIP string) (*VerifyResult, error) {
	// 必须处于 pending_captcha 状态
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

	return &VerifyResult{
		ChallengeID: challenge.ID,
		Data: map[string]any{
			types.ChallengeDataNext: string(challenge.ChannelType),
		},
	}, nil
}

// handleChallengeVerify 处理实际的 challenge 验证
func (s *Service) handleChallengeVerify(ctx context.Context, challenge *types.Challenge, req *VerifyRequest) (*VerifyResult, error) {
	// 如果还有 pending 前置条件未完成，不允许直接验证
	if pending, _ := challenge.GetData(types.ChallengeDataPendingCaptcha); pending == true {
		return nil, autherrors.NewInvalidRequest("captcha verification required before challenge verification")
	}

	proof, err := stringProof(req.Proof)
	if err != nil {
		return nil, err
	}

	verified, err := s.verifyWithProvider(ctx, challenge, proof)
	if err != nil {
		return nil, err
	}

	if verified {
		if err := s.cache.DeleteChallenge(ctx, challenge.ID); err != nil {
			logger.Warnf("[Challenge] 删除 challenge 失败: %v", err)
		}
	}

	return &VerifyResult{
		Verified:  verified,
		Challenge: challenge,
	}, nil
}

// verifyWithProvider 委托给注册的 mfa.Provider 执行验证
func (s *Service) verifyWithProvider(ctx context.Context, challenge *types.Challenge, proof string) (bool, error) {
	p := s.getMFAProvider(string(challenge.ChannelType))
	if p == nil {
		return false, autherrors.NewInvalidRequestf("unsupported channel type: %s", challenge.ChannelType)
	}

	switch challenge.ChannelType {
	case types.ChannelTypeTOTP:
		userID := challenge.Channel
		if userID == "" {
			return false, autherrors.NewInvalidRequest("channel (user_id) not found in challenge")
		}
		return p.Verify(ctx, proof, userID)
	case types.ChannelTypeEmailOTP:
		return p.Verify(ctx, proof, challenge.ID)
	default:
		return p.Verify(ctx, proof)
	}
}

// sendOTP 委托 Provider 发送验证码
func (s *Service) sendOTP(ctx context.Context, challenge *types.Challenge) error {
	p := s.getMFAProvider(string(challenge.ChannelType))
	if p == nil {
		return autherrors.NewInvalidRequestf("no provider for channel type: %s", challenge.ChannelType)
	}

	sender, ok := p.(otpSender)
	if !ok {
		return nil // 该类型不需要发送操作
	}

	email := challenge.Channel
	if email == "" {
		return autherrors.NewInvalidRequest("channel (email) not found in challenge")
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
