package cache

import (
	"context"

	"github.com/heliannuuthus/helios/internal/config"
	"github.com/heliannuuthus/helios/internal/hermes/models"
)

// ==================== Hermes 数据（本地缓存 + DB）====================

// GetApplication 获取应用（带缓存）
func (cm *Manager) GetApplication(ctx context.Context, appID string) (*models.ApplicationWithKey, error) {
	cacheKey := config.GetAegisCacheKeyPrefix("application") + appID

	// 尝试从缓存获取
	if cm.applicationCache != nil {
		if cached, ok := cm.applicationCache.Get(cacheKey); ok {
			return cached, nil
		}
	}

	// 从 hermes 获取
	result, err := cm.hermesSvc.GetApplicationWithKey(ctx, appID)
	if err != nil {
		return nil, err
	}

	// 存入缓存
	if cm.applicationCache != nil {
		ttl := config.GetAegisCacheTTL("application")
		cm.applicationCache.SetWithTTL(cacheKey, result, 1, ttl)
	}

	return result, nil
}

// GetService 获取服务（带缓存）
func (cm *Manager) GetService(ctx context.Context, serviceID string) (*models.ServiceWithKey, error) {
	cacheKey := config.GetAegisCacheKeyPrefix("service") + serviceID

	// 尝试从缓存获取
	if cm.serviceCache != nil {
		if cached, ok := cm.serviceCache.Get(cacheKey); ok {
			return cached, nil
		}
	}

	// 从 hermes 获取
	result, err := cm.hermesSvc.GetServiceWithKey(ctx, serviceID)
	if err != nil {
		return nil, err
	}

	// 存入缓存
	if cm.serviceCache != nil {
		ttl := config.GetAegisCacheTTL("service")
		cm.serviceCache.SetWithTTL(cacheKey, result, 1, ttl)
	}

	return result, nil
}

// GetDomain 获取域（带缓存）
func (cm *Manager) GetDomain(ctx context.Context, domainID string) (*models.DomainWithKey, error) {
	cacheKey := config.GetAegisCacheKeyPrefix("domain") + domainID

	// 尝试从缓存获取
	if cm.domainCache != nil {
		if cached, ok := cm.domainCache.Get(cacheKey); ok {
			return cached, nil
		}
	}

	// 从 hermes 获取
	result, err := cm.hermesSvc.GetDomainWithKey(ctx, domainID)
	if err != nil {
		return nil, err
	}

	// 存入缓存
	if cm.domainCache != nil {
		ttl := config.GetAegisCacheTTL("domain")
		cm.domainCache.SetWithTTL(cacheKey, result, 1, ttl)
	}

	return result, nil
}

// CheckAppServiceRelation 检查应用是否有权访问服务（使用复合 key 缓存优化）
func (cm *Manager) CheckAppServiceRelation(ctx context.Context, appID, serviceID string) (bool, error) {
	// 1. 先查复合 key 缓存
	cacheKey := appID + ":" + serviceID
	if cm.appServiceCache != nil {
		if cached, ok := cm.appServiceCache.Get(cacheKey); ok {
			return cached, nil
		}
	}

	// 2. 查数据库（通过 hermes 服务）
	relations, err := cm.GetAppServiceRelations(ctx, appID)
	if err != nil {
		return false, err
	}

	// 3. 检查关系是否存在
	exists := false
	for _, rel := range relations {
		if rel.ServiceID == serviceID {
			exists = true
			break
		}
	}

	// 4. 存入复合 key 缓存
	if cm.appServiceCache != nil {
		ttl := config.GetAegisCacheTTL("app-service")
		cm.appServiceCache.SetWithTTL(cacheKey, exists, 1, ttl)
	}

	return exists, nil
}

// GetAppServiceRelations 获取应用可访问的服务关系
func (cm *Manager) GetAppServiceRelations(ctx context.Context, appID string) ([]models.ApplicationServiceRelation, error) {
	cacheKey := config.GetAegisCacheKeyPrefix("application-service-relation") + appID

	// 尝试从缓存获取
	if cm.relationCache != nil {
		if cached, ok := cm.relationCache.Get(cacheKey); ok {
			return cached, nil
		}
	}

	// 从 hermes 获取
	relations, err := cm.hermesSvc.GetApplicationServiceRelations(ctx, appID)
	if err != nil {
		return nil, err
	}

	// 存入缓存
	if cm.relationCache != nil {
		ttl := config.GetAegisCacheTTL("application-service-relation")
		cm.relationCache.SetWithTTL(cacheKey, relations, 1, ttl)
	}

	return relations, nil
}

// ListRelationships 列出关系（代理到 hermes 服务）
func (cm *Manager) ListRelationships(ctx context.Context, serviceID, subjectType, subjectID string) ([]models.Relationship, error) {
	return cm.hermesSvc.ListRelationships(ctx, serviceID, subjectType, subjectID)
}

// FindUserByEmail 根据邮箱查找用户
func (cm *Manager) FindUserByEmail(ctx context.Context, email string) (*models.UserWithDecrypted, error) {
	result, err := cm.userSvc.FindByEmail(ctx, email)
	if err != nil {
		return nil, err
	}

	// 存入缓存
	if cm.userCache != nil {
		cacheKey := config.GetAegisCacheKeyPrefix("user") + result.OpenID
		ttl := config.GetAegisCacheTTL("user")
		cm.userCache.SetWithTTL(cacheKey, result, 1, ttl)
	}

	return result, nil
}

// GetAppAllowedOrigins 获取应用的允许跨域源（带缓存）
func (cm *Manager) GetAppAllowedOrigins(ctx context.Context, appID string) ([]string, error) {
	cacheKey := config.GetAegisCacheKeyPrefix("app-origins") + appID

	// 尝试从缓存获取
	if cm.appOriginsCache != nil {
		if cached, ok := cm.appOriginsCache.Get(cacheKey); ok {
			return cached, nil
		}
	}

	// 从应用缓存获取（复用已有的应用缓存逻辑）
	app, err := cm.GetApplication(ctx, appID)
	if err != nil {
		return nil, err
	}

	origins := app.GetAllowedOrigins()

	// 存入缓存
	if cm.appOriginsCache != nil {
		ttl := config.GetAegisCacheTTL("app-origins")
		cm.appOriginsCache.SetWithTTL(cacheKey, origins, 1, ttl)
	}

	return origins, nil
}

// ValidateAppOrigin 验证请求来源是否在应用的允许列表中
func (cm *Manager) ValidateAppOrigin(ctx context.Context, appID, origin string) (bool, error) {
	origins, err := cm.GetAppAllowedOrigins(ctx, appID)
	if err != nil {
		return false, err
	}

	// 如果未配置，则不限制
	if len(origins) == 0 {
		return true, nil
	}

	normalizedOrigin := normalizeOrigin(origin)
	for _, allowed := range origins {
		if normalizeOrigin(allowed) == normalizedOrigin {
			return true, nil
		}
		// 支持通配符 *
		if allowed == "*" {
			return true, nil
		}
	}

	return false, nil
}

// normalizeOrigin 规范化 origin（移除末尾斜杠）
func normalizeOrigin(origin string) string {
	if len(origin) > 0 && origin[len(origin)-1] == '/' {
		return origin[:len(origin)-1]
	}
	return origin
}

// GetApplicationIDPConfigs 获取应用 IDP 配置（带缓存）
func (cm *Manager) GetApplicationIDPConfigs(ctx context.Context, appID string) ([]*models.ApplicationIDPConfig, error) {
	cacheKey := config.GetAegisCacheKeyPrefix("app-idp-config") + appID

	// 尝试从缓存获取
	if cm.appIDPConfigCache != nil {
		if cached, ok := cm.appIDPConfigCache.Get(cacheKey); ok {
			return cached, nil
		}
	}

	// 从 hermes 获取
	configs, err := cm.hermesSvc.GetApplicationIDPConfigs(ctx, appID)
	if err != nil {
		return nil, err
	}

	// 存入缓存
	if cm.appIDPConfigCache != nil {
		ttl := config.GetAegisCacheTTL("app-idp-config")
		cm.appIDPConfigCache.SetWithTTL(cacheKey, configs, 1, ttl)
	}

	return configs, nil
}
