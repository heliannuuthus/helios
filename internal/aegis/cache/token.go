package cache

import (
	"context"
	"fmt"
	"time"

	"github.com/heliannuuthus/helios/internal/config"
	"github.com/heliannuuthus/helios/pkg/json"
	"github.com/heliannuuthus/helios/pkg/logger"
)

// ==================== AuthCode（Redis）====================

// AuthorizationCode 授权码
type AuthorizationCode struct {
	Code      string    `json:"code"`
	FlowID    string    `json:"flow_id"`
	State     string    `json:"state"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Used      bool      `json:"used"`
}

// SaveAuthCode 保存授权码
func (cm *Manager) SaveAuthCode(ctx context.Context, code *AuthorizationCode) error {
	prefix := config.GetAegisCacheKeyPrefix("auth_code")
	expiresIn := config.GetAegisAuthCodeExpiresIn()

	data, err := json.Marshal(code)
	if err != nil {
		return err
	}
	ttl := time.Until(code.ExpiresAt)
	if ttl <= 0 {
		ttl = expiresIn
	}
	return cm.redis.Set(ctx, prefix+code.Code, string(data), ttl)
}

// GetAuthCode 获取授权码
func (cm *Manager) GetAuthCode(ctx context.Context, code string) (*AuthorizationCode, error) {
	prefix := config.GetAegisCacheKeyPrefix("auth_code")
	data, err := cm.redis.Get(ctx, prefix+code)
	if err != nil {
		return nil, ErrAuthCodeNotFound
	}

	var authCode AuthorizationCode
	if err := json.Unmarshal([]byte(data), &authCode); err != nil {
		return nil, err
	}

	if time.Now().After(authCode.ExpiresAt) {
		return nil, ErrAuthCodeExpired
	}

	if authCode.Used {
		return nil, ErrAuthCodeUsed
	}

	return &authCode, nil
}

// MarkAuthCodeUsed 标记授权码已使用
func (cm *Manager) MarkAuthCodeUsed(ctx context.Context, code string) error {
	prefix := config.GetAegisCacheKeyPrefix("auth_code")
	authCode, err := cm.GetAuthCode(ctx, code)
	if err != nil {
		return err
	}

	authCode.Used = true
	data, err := json.Marshal(authCode)
	if err != nil {
		return fmt.Errorf("marshal auth code: %w", err)
	}

	remaining := time.Until(authCode.ExpiresAt)
	if remaining <= 0 {
		remaining = time.Second
	}

	return cm.redis.Set(ctx, prefix+code, string(data), remaining)
}

// ==================== RefreshToken（Redis）====================

// RefreshToken 刷新令牌
type RefreshToken struct {
	Token     string    `json:"token"`
	UserID    string    `json:"user_id"`
	ClientID  string    `json:"client_id"`
	Audience  string    `json:"audience"`
	Scope     string    `json:"scope"`
	ExpiresAt time.Time `json:"expires_at"`
	Revoked   bool      `json:"revoked"`
	CreatedAt time.Time `json:"created_at"`
}

// IsValid 检查是否有效
func (r *RefreshToken) IsValid() bool {
	return !r.Revoked && time.Now().Before(r.ExpiresAt)
}

// SaveRefreshToken 保存刷新令牌
func (cm *Manager) SaveRefreshToken(ctx context.Context, token *RefreshToken) error {
	rtPrefix := config.GetAegisCacheKeyPrefix("refresh_token")
	userPrefix := config.GetAegisCacheKeyPrefix("user_token")

	data, err := json.Marshal(token)
	if err != nil {
		return err
	}

	ttl := time.Until(token.ExpiresAt)
	if ttl <= 0 {
		ttl = time.Second
	}

	if err := cm.redis.Set(ctx, rtPrefix+token.Token, string(data), ttl); err != nil {
		return err
	}

	// 添加到用户的 token 集合
	return cm.redis.SAdd(ctx, userPrefix+token.UserID, token.Token)
}

// GetRefreshToken 获取刷新令牌
func (cm *Manager) GetRefreshToken(ctx context.Context, token string) (*RefreshToken, error) {
	prefix := config.GetAegisCacheKeyPrefix("refresh_token")
	data, err := cm.redis.Get(ctx, prefix+token)
	if err != nil {
		return nil, ErrRefreshTokenNotFound
	}

	var rt RefreshToken
	if err := json.Unmarshal([]byte(data), &rt); err != nil {
		return nil, err
	}

	if time.Now().After(rt.ExpiresAt) {
		return nil, ErrRefreshTokenExpired
	}

	if rt.Revoked {
		return nil, ErrRefreshTokenRevoked
	}

	return &rt, nil
}

// RevokeRefreshToken 撤销刷新令牌
func (cm *Manager) RevokeRefreshToken(ctx context.Context, token string) error {
	prefix := config.GetAegisCacheKeyPrefix("refresh_token")
	data, err := cm.redis.Get(ctx, prefix+token)
	if err != nil {
		return nil
	}

	var rt RefreshToken
	if err := json.Unmarshal([]byte(data), &rt); err != nil {
		return err
	}

	rt.Revoked = true
	newData, err := json.Marshal(rt)
	if err != nil {
		return fmt.Errorf("marshal refresh token: %w", err)
	}

	remaining := time.Until(rt.ExpiresAt)
	if remaining <= 0 {
		remaining = time.Second
	}

	return cm.redis.Set(ctx, prefix+token, string(newData), remaining)
}

// RevokeUserRefreshTokens 撤销用户所有刷新令牌
func (cm *Manager) RevokeUserRefreshTokens(ctx context.Context, userID string) error {
	prefix := config.GetAegisCacheKeyPrefix("user_token")
	tokens, err := cm.redis.SMembers(ctx, prefix+userID)
	if err != nil {
		return nil
	}

	for _, token := range tokens {
		if err := cm.RevokeRefreshToken(ctx, token); err != nil {
			logger.Warnf("[Manager] revoke refresh token failed: %v", err)
		}
	}

	return nil
}

// ListUserRefreshTokens 列出用户的刷新令牌
func (cm *Manager) ListUserRefreshTokens(ctx context.Context, userID, clientID string) ([]*RefreshToken, error) {
	prefix := config.GetAegisCacheKeyPrefix("user_token")
	tokens, err := cm.redis.SMembers(ctx, prefix+userID)
	if err != nil {
		return nil, nil
	}

	var result []*RefreshToken
	for _, token := range tokens {
		rt, err := cm.GetRefreshToken(ctx, token)
		if err != nil {
			continue
		}
		if clientID == "" || rt.ClientID == clientID {
			result = append(result, rt)
		}
	}

	return result, nil
}
