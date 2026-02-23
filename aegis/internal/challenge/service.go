package challenge

import (
	"context"
	"time"

	autherrors "github.com/heliannuuthus/helios/aegis/errors"
	"github.com/heliannuuthus/helios/aegis/internal/authenticator"
	"github.com/heliannuuthus/helios/aegis/internal/cache"
	"github.com/heliannuuthus/helios/aegis/internal/types"
	"github.com/heliannuuthus/helios/pkg/logger"
)

// DefaultChallengeTokenTTL ChallengeToken expiration duration
const DefaultChallengeTokenTTL = 5 * time.Minute

// Service provides atomic challenge operations.
// Handler is responsible for orchestrating these operations.
type Service struct {
	cache    *cache.Manager
	registry *authenticator.Registry
}

// NewService creates a new Challenge Service
func NewService(cache *cache.Manager, registry *authenticator.Registry) *Service {
	return &Service{
		cache:    cache,
		registry: registry,
	}
}

// ==================== internal helpers ====================

// getChallengeVerifier resolves a ChallengeVerifier from the Registry
func (s *Service) getChallengeVerifier(connection string) (authenticator.ChallengeVerifier, error) {
	a, ok := s.registry.Get(connection)
	if !ok {
		return nil, autherrors.NewInvalidRequestf("unsupported connection: %s", connection)
	}
	verifier, ok := a.(authenticator.ChallengeVerifier)
	if !ok {
		return nil, autherrors.NewInvalidRequestf("connection %s does not support challenge verification", connection)
	}
	return verifier, nil
}

// getExchanger resolves an Exchanger from the Registry
func (s *Service) getExchanger(channelType string) (authenticator.Exchanger, error) {
	a, ok := s.registry.Get(channelType)
	if !ok {
		return nil, autherrors.NewInvalidRequestf("unsupported channel type: %s", channelType)
	}
	exchanger, ok := a.(authenticator.Exchanger)
	if !ok {
		return nil, autherrors.NewInvalidRequestf("channel type %s does not support exchange", channelType)
	}
	return exchanger, nil
}

// ==================== atomic operations ====================

// BuildRequired 构建前置条件（如 captcha），并设置到 Challenge 上
// 返回 true 表示有前置条件需要满足
func (s *Service) BuildRequired(challenge *types.Challenge) bool {
	switch challenge.ChannelType {
	case types.ChannelTypeEmailOTP, types.ChannelTypeSmsOTP, types.ChannelTypeTgOTP:
		captchaConnection := string(types.ChannelTypeCaptcha)
		a, ok := s.registry.Get(captchaConnection)
		if !ok {
			return false
		}
		cfg := a.Prepare()
		if cfg == nil {
			return false
		}
		challenge.Required = types.ChallengeRequired{
			captchaConnection: &types.ChallengeRequiredConfig{
				Identifier: cfg.Identifier,
				Strategy:   cfg.Strategy,
			},
		}
		return true
	default:
		return false
	}
}

// Initiate resolves the verifier and executes Initiate, returns retryAfter (冷却时间)
// 被限流时返回 TooManyRequestsError
func (s *Service) Initiate(ctx context.Context, challenge *types.Challenge) (retryAfter int, err error) {
	verifier, err := s.getChallengeVerifier(string(challenge.ChannelType))
	if err != nil {
		return 0, err
	}
	return verifier.Initiate(ctx, challenge)
}

// Verify verifies Challenge proof (prerequisite or main proof)
// For prerequisite: pass req.Type (e.g., "captcha") and req.Strategy
// For main proof: pass challenge.ChannelType as verifier key
func (s *Service) Verify(ctx context.Context, challenge *types.Challenge, req *VerifyRequest) (bool, error) {
	// 确定使用哪个 verifier
	verifierKey := req.Type
	isPrerequisite := challenge.Required.Contains(req.Type)

	// 前置条件验证：校验 strategy 是否匹配
	if isPrerequisite {
		if reqCfg, ok := challenge.Required[req.Type]; ok && len(reqCfg.Strategy) > 0 {
			if req.Strategy == "" {
				return false, autherrors.NewInvalidRequest("strategy is required for prerequisite verification")
			}
			strategyValid := false
			for _, st := range reqCfg.Strategy {
				if st == req.Strategy {
					strategyValid = true
					break
				}
			}
			if !strategyValid {
				return false, autherrors.NewInvalidRequestf("unsupported strategy: %s", req.Strategy)
			}
		}
		// 将 strategy 存入 challenge.Data，供 verifier 读取
		if req.Strategy != "" {
			challenge.SetData("strategy", req.Strategy)
		}
	} else {
		// 主验证：使用 challenge.ChannelType 作为 verifier key
		verifierKey = string(challenge.ChannelType)
	}

	proof, err := stringProof(req.Proof)
	if err != nil {
		return false, err
	}

	verifier, err := s.getChallengeVerifier(verifierKey)
	if err != nil {
		return false, err
	}

	ok, err := verifier.Verify(ctx, challenge, proof)
	if err != nil {
		logger.Warnf("[Challenge] verification failed for %s: %v", verifierKey, err)
		return false, err
	}

	// 前置条件验证通过，标记为已验证
	if ok && isPrerequisite {
		challenge.Required[req.Type].Verified = true
	}

	return ok, nil
}

// Exchange executes the exchange flow (one-step: code → principal)
func (s *Service) Exchange(ctx context.Context, channelType, code string) (principal string, err error) {
	exchanger, err := s.getExchanger(channelType)
	if err != nil {
		return "", err
	}
	return exchanger.Exchange(ctx, code)
}

// Save persists the Challenge to cache
func (s *Service) Save(ctx context.Context, challenge *types.Challenge) error {
	if err := s.cache.SaveChallenge(ctx, challenge); err != nil {
		return autherrors.NewServerErrorf("save challenge: %v", err)
	}
	return nil
}

// Delete removes the Challenge from cache
func (s *Service) Delete(ctx context.Context, challengeID string) error {
	if err := s.cache.DeleteChallenge(ctx, challengeID); err != nil {
		logger.Warnf("[Challenge] delete challenge failed: %v", err)
		return err
	}
	return nil
}

// ==================== query ====================

// GetAndValidate retrieves a Challenge by ID and validates it
func (s *Service) GetAndValidate(ctx context.Context, challengeID string) (*types.Challenge, error) {
	ch, err := s.cache.GetChallenge(ctx, challengeID)
	if err != nil {
		return nil, autherrors.NewNotFound("challenge not found")
	}
	if ch.IsExpired() {
		return nil, autherrors.NewChallengeExpired("challenge expired")
	}
	return ch, nil
}

// ==================== helpers ====================

// stringProof extracts a string proof from the generic Proof field
func stringProof(proof any) (string, error) {
	str, ok := proof.(string)
	if !ok {
		return "", autherrors.NewInvalidRequest("proof must be a string")
	}
	if str == "" {
		return "", autherrors.NewInvalidRequest("proof must not be empty")
	}
	return str, nil
}
