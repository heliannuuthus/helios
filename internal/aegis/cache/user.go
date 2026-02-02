package cache

import (
	"context"

	"github.com/heliannuuthus/helios/internal/config"
	"github.com/heliannuuthus/helios/internal/hermes/models"
)

// ==================== User（本地缓存 + DB）====================

// GetUser 获取用户（带缓存）
func (cm *Manager) GetUser(ctx context.Context, openID string) (*models.UserWithDecrypted, error) {
	cacheKey := config.GetAegisCacheKeyPrefix("user") + openID

	// 尝试从缓存获取
	if cm.userCache != nil {
		if cached, ok := cm.userCache.Get(cacheKey); ok {
			return cached, nil
		}
	}

	// 从 UserService 获取
	result, err := cm.userSvc.GetUserWithDecrypted(ctx, openID)
	if err != nil {
		return nil, err
	}

	// 存入缓存
	if cm.userCache != nil {
		ttl := config.GetAegisCacheTTL("user")
		cm.userCache.SetWithTTL(cacheKey, result, 1, ttl)
	}

	return result, nil
}

// GetUserByIdentity 根据身份获取用户（带缓存）
func (cm *Manager) GetUserByIdentity(ctx context.Context, idp, providerID string) (*models.UserWithDecrypted, error) {
	// 先从 DB 查找（身份关联不缓存）
	result, err := cm.userSvc.GetUserWithDecryptedByIdentity(ctx, idp, providerID)
	if err != nil {
		return nil, err
	}

	// 存入用户缓存
	if cm.userCache != nil {
		cacheKey := config.GetAegisCacheKeyPrefix("user") + result.OpenID
		ttl := config.GetAegisCacheTTL("user")
		cm.userCache.SetWithTTL(cacheKey, result, 1, ttl)
	}

	return result, nil
}

// GetUserIdentities 获取用户已绑定的身份类型列表
func (cm *Manager) GetUserIdentities(ctx context.Context, openID string) ([]string, error) {
	// 从 UserService 获取用户的身份绑定信息
	identities, err := cm.userSvc.GetIdentities(ctx, openID)
	if err != nil {
		return nil, err
	}

	// 提取 IDP 类型列表
	idpTypes := make([]string, 0, len(identities))
	for _, identity := range identities {
		idpTypes = append(idpTypes, identity.IDP)
	}
	return idpTypes, nil
}

// FindOrCreateUser 查找或创建用户
func (cm *Manager) FindOrCreateUser(ctx context.Context, req *models.FindOrCreateUserRequest) (*models.UserWithDecrypted, bool, error) {
	user, isNew, err := cm.userSvc.FindOrCreate(ctx, req)
	if err != nil {
		return nil, false, err
	}

	// 存入缓存
	if cm.userCache != nil {
		cacheKey := config.GetAegisCacheKeyPrefix("user") + user.OpenID
		ttl := config.GetAegisCacheTTL("user")
		cm.userCache.SetWithTTL(cacheKey, user, 1, ttl)
	}

	return user, isNew, nil
}

// InvalidateUser 清除用户缓存
func (cm *Manager) InvalidateUser(ctx context.Context, openID string) {
	if cm.userCache != nil {
		cacheKey := config.GetAegisCacheKeyPrefix("user") + openID
		cm.userCache.Del(cacheKey)
	}
}
