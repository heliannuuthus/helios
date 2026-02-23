package cache

import (
	"context"
	"fmt"
	"time"

	"github.com/heliannuuthus/helios/aegis/config"
	"github.com/heliannuuthus/helios/aegis/internal/types"
)

// ==================== Challenge（Redis 临时会话）====================

// SaveChallenge 保存 Challenge
func (cm *Manager) SaveChallenge(ctx context.Context, challenge *types.Challenge) error {
	prefix := config.GetCacheKeyPrefix("challenge")

	data, err := challenge.MarshalForStorage()
	if err != nil {
		return err
	}

	ttl := time.Until(challenge.ExpiresAt)
	if ttl <= 0 {
		ttl = config.GetChallengeBusinessExpiresIn()
	}

	return cm.redis.Set(ctx, prefix+challenge.ID, string(data), ttl)
}

// GetChallenge 获取 Challenge
func (cm *Manager) GetChallenge(ctx context.Context, challengeID string) (*types.Challenge, error) {
	prefix := config.GetCacheKeyPrefix("challenge")
	data, err := cm.redis.Get(ctx, prefix+challengeID)
	if err != nil {
		return nil, fmt.Errorf("challenge not found")
	}

	var challenge types.Challenge
	if err := challenge.UnmarshalFromStorage([]byte(data)); err != nil {
		return nil, err
	}

	return &challenge, nil
}

// DeleteChallenge 删除 Challenge
func (cm *Manager) DeleteChallenge(ctx context.Context, challengeID string) error {
	prefix := config.GetCacheKeyPrefix("challenge")
	return cm.redis.Del(ctx, prefix+challengeID)
}

// ==================== OTP（Redis）====================

// SaveOTP 保存验证码
func (cm *Manager) SaveOTP(ctx context.Context, key, code string) error {
	prefix := config.GetCacheKeyPrefix("otp")
	expiresIn := config.GetOTPExpiresIn()
	return cm.redis.Set(ctx, prefix+key, code, expiresIn)
}

// GetOTP 获取验证码
func (cm *Manager) GetOTP(ctx context.Context, key string) (string, error) {
	prefix := config.GetCacheKeyPrefix("otp")
	code, err := cm.redis.Get(ctx, prefix+key)
	if err != nil {
		return "", ErrOTPNotFound
	}
	return code, nil
}

// DeleteOTP 删除验证码
func (cm *Manager) DeleteOTP(ctx context.Context, key string) error {
	prefix := config.GetCacheKeyPrefix("otp")
	return cm.redis.Del(ctx, prefix+key)
}

// VerifyOTP 验证并删除验证码
func (cm *Manager) VerifyOTP(ctx context.Context, key, code string) error {
	stored, err := cm.GetOTP(ctx, key)
	if err != nil {
		return err
	}
	if stored != code {
		return fmt.Errorf("invalid otp")
	}
	return cm.DeleteOTP(ctx, key)
}
