package cache

import (
	"context"

	"github.com/heliannuuthus/helios/aegis/config"
	"github.com/heliannuuthus/helios/aegis/models"
)

// ==================== User（read-through 缓存）====================

// CacheUser 将用户写入本地缓存
func (cm *Manager) CacheUser(user *models.UserWithDecrypted) {
	if cm.userCache != nil && user != nil {
		cacheKey := config.GetCacheKeyPrefix("user") + user.OpenID
		ttl := config.GetCacheTTL("user")
		cm.userCache.SetWithTTL(cacheKey, user, 1, ttl)
	}
}

// GetUser 获取用户（带缓存）
func (cm *Manager) GetUser(ctx context.Context, openid string) (*models.UserWithDecrypted, error) {
	cacheKey := config.GetCacheKeyPrefix("user") + openid

	// 尝试从缓存获取
	if cm.userCache != nil {
		if cached, ok := cm.userCache.Get(cacheKey); ok {
			return cached, nil
		}
	}

	// 从 UserService 获取
	result, err := cm.userSvc.GetDecryptedUserByOpenID(ctx, openid)
	if err != nil {
		return nil, err
	}

	cm.CacheUser(result)
	return result, nil
}

// InvalidateUser 清除用户缓存
func (cm *Manager) InvalidateUser(ctx context.Context, openid string) {
	if cm.userCache != nil {
		cacheKey := config.GetCacheKeyPrefix("user") + openid
		cm.userCache.Del(cacheKey)
	}
}
