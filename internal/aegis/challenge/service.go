package challenge

import (
	"context"
	"time"

	"github.com/heliannuuthus/helios/internal/aegis/authenticate"
	"github.com/heliannuuthus/helios/internal/aegis/authenticator"
	"github.com/heliannuuthus/helios/internal/aegis/authenticator/captcha"
	"github.com/heliannuuthus/helios/internal/aegis/authenticator/factor"
	"github.com/heliannuuthus/helios/internal/aegis/cache"
	autherrors "github.com/heliannuuthus/helios/internal/aegis/errors"
	"github.com/heliannuuthus/helios/internal/aegis/types"
	"github.com/heliannuuthus/helios/internal/config"
	"github.com/heliannuuthus/helios/pkg/aegis/token"
	"github.com/heliannuuthus/helios/pkg/logger"
	"github.com/heliannuuthus/helios/pkg/throttle"
)

// ChallengeToken 签发有效期
const DefaultChallengeTokenTTL = 5 * time.Minute

// Service Challenge 服务
type Service struct {
	cache     *cache.Manager
	registry  *authenticator.Registry
	throttler *throttle.Throttler
}

// NewService 创建 Challenge 服务
func NewService(cache *cache.Manager, registry *authenticator.Registry, throttler *throttle.Throttler) *Service {
	return &Service{
		cache:     cache,
		registry:  registry,
		throttler: throttler,
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

// getCaptchaRequired 构建 captcha 前置条件
func (s *Service) getCaptchaRequired() *ChallengeRequired {
	verifier := s.getCaptchaVerifier()
	if verifier == nil {
		return nil
	}
	return &ChallengeRequired{
		Captcha: &CaptchaConfig{
			Strategy:   []string{verifier.GetProvider()},
			Identifier: verifier.GetIdentifier(),
		},
		Verified: false,
	}
}

// getFactorProvider 从 Registry 获取指定类型的 factor.Provider
func (s *Service) getFactorProvider(connection string) factor.Provider {
	a, ok := s.registry.Get(connection)
	if !ok {
		return nil
	}
	factorAuth, ok := a.(*authenticate.FactorAuthenticator)
	if !ok {
		return nil
	}
	return factorAuth.Provider()
}

// ==================== 校验 ====================

// validateRequest 校验 Create 请求参数合法性
// - 校验应用和服务存在（不校验权限关系）
// - 验证类：校验 type 非空，且该服务已配置此 challenge type
func (s *Service) validateRequest(ctx context.Context, req *CreateRequest) error {
	// 1. 校验应用存在
	_, err := s.cache.GetApplication(ctx, req.ClientID)
	if err != nil {
		return autherrors.NewInvalidRequestf("invalid client_id: %s", req.ClientID)
	}

	// 2. 校验服务存在
	_, err = s.cache.GetService(ctx, req.Audience)
	if err != nil {
		return autherrors.NewInvalidRequestf("invalid audience: %s", req.Audience)
	}

	// 3. 验证类：校验 type 非空，且服务配置了该 challenge type
	if token.ChannelType(req.ChannelType).IsVerification() {
		if req.Type == "" {
			return autherrors.NewInvalidRequest("type is required for verification channel")
		}
		_, err = s.cache.GetChallengeConfig(ctx, req.Audience, req.Type)
		if err != nil {
			return autherrors.NewInvalidRequestf("challenge type %q is not configured for service %s", req.Type, req.Audience)
		}
	}

	// 4. 校验 Provider 已注册
	if s.getFactorProvider(req.ChannelType) == nil {
		return autherrors.NewInvalidRequestf("unsupported channel type: %s", req.ChannelType)
	}

	return nil
}

// ==================== 限流 ====================

// checkIPRateLimit 检查 IP 维度频率限流（全局共享）
// 返回 retryAfter > 0 表示被限流
func (s *Service) checkIPRateLimit(ctx context.Context, remoteIP string) int {
	if s.throttler == nil || remoteIP == "" {
		return 0
	}

	ipLimits := config.GetRateLimitIPLimits()
	ipKey := types.RateLimitKeyPrefixCreateIP + remoteIP

	result, err := s.throttler.Allow(ctx, ipKey, ipLimits)
	if err != nil {
		logger.Warnf("[Challenge] IP 限流检查失败: %v", err)
		return 0
	}
	if !result.Allowed {
		return result.RetryAfter
	}

	return 0
}

// ==================== 限流（Verify 失败计数） ====================

// recordVerifyFail 记录验证失败并检查是否需要重新触发 captcha
// 返回 needCaptcha=true 表示错误次数达到阈值
func (s *Service) recordVerifyFail(ctx context.Context, challenge *types.Challenge) (needCaptcha bool) {
	if s.throttler == nil {
		return false
	}

	failWindow := config.GetRateLimitVerifyFailWindow()
	threshold := config.GetRateLimitVerifyFailThreshold()

	failKey := types.RateLimitKeyPrefixVerifyFail + challenge.Audience + ":" + challenge.Channel
	count, err := s.throttler.Record(ctx, failKey, failWindow)
	if err != nil {
		logger.Warnf("[Challenge] 记录验证失败次数失败: %v", err)
		return false
	}

	return count >= int64(threshold)
}

// ==================== Create ====================

// Create 创建 Challenge
// 1. 校验参数
// 2. 如果需要 captcha 前置 → 先构建 Challenge 并设置 Required，不触发 Provider.Initiate
// 3. 不需要 captcha → 委托 Provider.Initiate（校验 channel、限流、副作用、构建 Challenge）
func (s *Service) Create(ctx context.Context, req *CreateRequest, remoteIP string) (*CreateResponse, error) {
	if err := s.validateRequest(ctx, req); err != nil {
		return nil, err
	}

	channelType := token.ChannelType(req.ChannelType)

	// 需要 captcha 前置：先创建一个空壳 Challenge，设置 Required，等 captcha 通过后再 Initiate
	if channelType.RequiresCaptcha() && s.getCaptchaVerifier() != nil {
		challenge := types.NewChallenge(req.ClientID, req.Audience, req.Type, types.ChannelType(req.ChannelType), req.Channel, config.GetChallengeExpiresIn())
		challenge.Required = s.getCaptchaRequired()

		if err := s.cache.SaveChallenge(ctx, challenge); err != nil {
			return nil, autherrors.NewServerErrorf("save challenge: %v", err)
		}

		return &CreateResponse{
			ChallengeID: challenge.ID,
			Required:    challenge.Required.ForClient(),
		}, nil
	}

	// 不需要 captcha，先检查 IP 限流，再委托 Provider.Initiate
	if retryAfter := s.checkIPRateLimit(ctx, remoteIP); retryAfter > 0 {
		return &CreateResponse{RetryAfter: retryAfter}, nil
	}

	return s.initiateWithProvider(ctx, req)
}

// initiateWithProvider 委托 Provider 完成 Initiate（校验 channel、限流、副作用、构建 Challenge）
func (s *Service) initiateWithProvider(ctx context.Context, req *CreateRequest) (*CreateResponse, error) {
	provider := s.getFactorProvider(req.ChannelType)

	result, err := provider.Initiate(ctx, req.Channel, req.ClientID, req.Audience, req.Type)
	if err != nil {
		return nil, autherrors.NewInvalidRequestf("initiate failed: %v", err)
	}

	if err := s.cache.SaveChallenge(ctx, result.Challenge); err != nil {
		return nil, autherrors.NewServerErrorf("save challenge: %v", err)
	}

	resp := &CreateResponse{
		ChallengeID: result.Challenge.ID,
		RetryAfter:  result.RetryAfter,
	}
	return resp, nil
}

// ==================== Verify ====================

// Verify 验证 Challenge
// 根据 Challenge.Required 状态决定走哪个分支：
//   - NeedsCaptcha() 且 req.Type 非空 → 验证 captcha
//   - NeedsCaptcha() 且 req.Type 为空 → 返回 required 引导前端渲染 captcha
//   - captcha 已过或无需 captcha → 执行实际因子验证
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

	// 前置 captcha 未完成
	if challenge.NeedsCaptcha() {
		if req.Type != "" {
			return s.handleCaptchaVerify(ctx, challenge, req, remoteIP)
		}
		return &VerifyResult{
			Verified: false,
			Required: challenge.Required.ForClient(),
		}, nil
	}

	// 前置已完成，执行实际因子验证
	return s.handleChallengeVerify(ctx, challenge, req)
}

// handleCaptchaVerify 处理 captcha 验证（前置条件验证）
// captcha 通过后，委托 Provider.Initiate 完成副作用（发邮件等）
func (s *Service) handleCaptchaVerify(ctx context.Context, challenge *types.Challenge, req *VerifyRequest, remoteIP string) (*VerifyResult, error) {
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

	// captcha 通过，标记 Verified = true
	challenge.Required.Verified = true

	// 检查 IP 维度限流（captcha 通过后、Initiate 之前）
	if retryAfter := s.checkIPRateLimit(ctx, remoteIP); retryAfter > 0 {
		if err := s.cache.SaveChallenge(ctx, challenge); err != nil {
			return nil, autherrors.NewServerErrorf("save challenge: %v", err)
		}
		return &VerifyResult{Verified: false, RetryAfter: retryAfter}, nil
	}

	// 委托 Provider.Initiate 执行副作用（channel 限流、发邮件等）
	provider := s.getFactorProvider(string(challenge.ChannelType))
	if provider == nil {
		return nil, autherrors.NewServerErrorf("provider not found for channel type: %s", challenge.ChannelType)
	}

	result, err := provider.Initiate(ctx, challenge.Channel, challenge.ClientID, challenge.Audience, challenge.Type)
	if err != nil {
		return nil, autherrors.NewServerErrorf("initiate after captcha failed: %v", err)
	}

	// Initiate 返回的 Challenge 会有新 ID，但我们需要保持原 Challenge ID（前端已持有）
	// 所以只更新原 Challenge 的状态，不替换
	if result.RetryAfter > 0 {
		if err := s.cache.SaveChallenge(ctx, challenge); err != nil {
			return nil, autherrors.NewServerErrorf("save challenge: %v", err)
		}
		return &VerifyResult{
			Verified:   false,
			RetryAfter: result.RetryAfter,
		}, nil
	}

	if err := s.cache.SaveChallenge(ctx, challenge); err != nil {
		return nil, autherrors.NewServerErrorf("save challenge: %v", err)
	}

	return &VerifyResult{Verified: false}, nil
}

// handleChallengeVerify 处理实际的 challenge 验证
func (s *Service) handleChallengeVerify(ctx context.Context, challenge *types.Challenge, req *VerifyRequest) (*VerifyResult, error) {
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
		return &VerifyResult{
			Verified:  true,
			Challenge: challenge,
		}, nil
	}

	// 验证失败，记录错误次数
	if needCaptcha := s.recordVerifyFail(ctx, challenge); needCaptcha {
		challenge.Required = s.getCaptchaRequired()
		if err := s.cache.SaveChallenge(ctx, challenge); err != nil {
			logger.Warnf("[Challenge] 保存 challenge 失败: %v", err)
		}
		return &VerifyResult{
			Verified: false,
			Required: challenge.Required.ForClient(),
		}, nil
	}

	return &VerifyResult{Verified: false}, nil
}

// verifyWithProvider 委托给注册的 factor.Provider 执行验证
// 统一传入 channel 和 challengeID，各 Provider 通过 ...params 自行取用
func (s *Service) verifyWithProvider(ctx context.Context, challenge *types.Challenge, proof string) (bool, error) {
	p := s.getFactorProvider(string(challenge.ChannelType))
	if p == nil {
		return false, autherrors.NewInvalidRequestf("unsupported channel type: %s", challenge.ChannelType)
	}

	return p.Verify(ctx, proof, challenge.Channel, challenge.ID)
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
