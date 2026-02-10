package cache

import (
	"context"
	"errors"
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
}

// SaveAuthCode 保存授权码
func (cm *Manager) SaveAuthCode(ctx context.Context, code *AuthorizationCode) error {
	prefix := config.GetAegisCacheKeyPrefix("auth_code")

	ttl := time.Until(code.ExpiresAt)
	if ttl <= 0 {
		return fmt.Errorf("auth code already expired, ExpiresAt: %v", code.ExpiresAt)
	}

	data, err := json.Marshal(code)
	if err != nil {
		return err
	}
	return cm.redis.Set(ctx, prefix+code.Code, string(data), ttl)
}

// ConsumeAuthCode 原子消费授权码（读取并删除，防止重放攻击）
// 使用 Lua 脚本保证 get-and-delete 的原子性，授权码只能被消费一次
func (cm *Manager) ConsumeAuthCode(ctx context.Context, code string) (*AuthorizationCode, error) {
	prefix := config.GetAegisCacheKeyPrefix("auth_code")
	key := prefix + code
	// Lua 脚本: 读取 -> 删除 -> 返回数据；不存在则返回 nil
	script := "local d=redis.call('GET',KEYS[1]) if not d then return nil end redis.call('DEL',KEYS[1]) return d"
	result, err := cm.redis.Eval(ctx, script, []string{key})
	if err != nil {
		logger.Errorf("[Manager] ConsumeAuthCode redis eval failed: %v", err)
		return nil, fmt.Errorf("consume auth code failed: %w", err)
	}

	data, ok := result.(string)
	if !ok {
		return nil, ErrAuthCodeNotFound
	}

	var authCode AuthorizationCode
	if err := json.Unmarshal([]byte(data), &authCode); err != nil {
		return nil, err
	}

	if time.Now().After(authCode.ExpiresAt) {
		return nil, ErrAuthCodeExpired
	}

	return &authCode, nil
}

// ==================== RefreshToken（Redis）====================

// RefreshToken 刷新令牌
type RefreshToken struct {
	Token     string    `json:"token"`
	OpenID    string    `json:"openid"`    // 用户标识（t_user.openid = global identity 的 t_openid）
	ClientID  string    `json:"client_id"`
	Audience  string    `json:"audience"`
	Scope     string    `json:"scope"`
	ExpiresAt time.Time `json:"expires_at"`
	Revoked   bool      `json:"revoked"`
	CreatedAt time.Time `json:"created_at"`
}

// SaveRefreshToken 保存刷新令牌
func (cm *Manager) SaveRefreshToken(ctx context.Context, token *RefreshToken) error {
	rtPrefix := config.GetAegisCacheKeyPrefix("refresh_token")
	userPrefix := config.GetAegisCacheKeyPrefix("user_token")

	ttl := time.Until(token.ExpiresAt)
	if ttl <= 0 {
		return fmt.Errorf("refresh token already expired, ExpiresAt: %v", token.ExpiresAt)
	}

	data, err := json.Marshal(token)
	if err != nil {
		return err
	}

	if err := cm.redis.Set(ctx, rtPrefix+token.Token, string(data), ttl); err != nil {
		return err
	}

	// 添加到用户的 token 集合
	return cm.redis.SAdd(ctx, userPrefix+token.OpenID, token.Token)
}

// GetRefreshToken 获取刷新令牌
func (cm *Manager) GetRefreshToken(ctx context.Context, token string) (*RefreshToken, error) {
	prefix := config.GetAegisCacheKeyPrefix("refresh_token")
	data, err := cm.redis.Get(ctx, prefix+token)
	if err != nil {
		logger.Errorf("[Manager] GetRefreshToken redis get failed: %v", err)
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
		logger.Warnf("[Manager] RevokeRefreshToken redis get failed (token may have expired): %v", err)
		return fmt.Errorf("get refresh token for revocation: %w", err)
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
		// token 已过期，无需再保存
		return nil
	}

	return cm.redis.Set(ctx, prefix+token, string(newData), remaining)
}

// RevokeUserRefreshTokens 撤销用户所有刷新令牌
func (cm *Manager) RevokeUserRefreshTokens(ctx context.Context, openid string) error {
	prefix := config.GetAegisCacheKeyPrefix("user_token")
	tokens, err := cm.redis.SMembers(ctx, prefix+openid)
	if err != nil {
		logger.Errorf("[Manager] RevokeUserRefreshTokens redis smembers failed: %v", err)
		return fmt.Errorf("list user refresh tokens: %w", err)
	}

	var errs []error
	for _, token := range tokens {
		if err := cm.RevokeRefreshToken(ctx, token); err != nil {
			logger.Warnf("[Manager] revoke refresh token failed: %v", err)
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("failed to revoke %d/%d tokens: %w", len(errs), len(tokens), errors.Join(errs...))
	}
	return nil
}

// ListUserRefreshTokens 列出用户的刷新令牌
func (cm *Manager) ListUserRefreshTokens(ctx context.Context, openid, clientID string) ([]*RefreshToken, error) {
	prefix := config.GetAegisCacheKeyPrefix("user_token")
	tokens, err := cm.redis.SMembers(ctx, prefix+openid)
	if err != nil {
		logger.Errorf("[Manager] ListUserRefreshTokens redis smembers failed: %v", err)
		return nil, fmt.Errorf("list user refresh tokens: %w", err)
	}

	var result []*RefreshToken
	for _, token := range tokens {
		rt, err := cm.GetRefreshToken(ctx, token)
		if err != nil {
			// 过期或已撤销的 token 跳过（属于正常清理场景）
			continue
		}
		if clientID == "" || rt.ClientID == clientID {
			result = append(result, rt)
		}
	}

	return result, nil
}
