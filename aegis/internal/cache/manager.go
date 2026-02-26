package cache

import (
	"errors"

	"github.com/dgraph-io/ristretto/v2"

	"github.com/heliannuuthus/helios/aegis/config"
	"github.com/heliannuuthus/helios/hermes"
	"github.com/heliannuuthus/helios/hermes/models"
	"github.com/heliannuuthus/helios/pkg/logger"
	pkgredis "github.com/heliannuuthus/helios/pkg/redis"
)

// 错误定义
var (
	ErrAuthFlowNotFound     = errors.New("auth flow not found")
	ErrAuthFlowExpired      = errors.New("auth flow expired")
	ErrAuthCodeNotFound     = errors.New("authorization code not found")
	ErrAuthCodeExpired      = errors.New("authorization code expired")
	ErrRefreshTokenNotFound = errors.New("refresh token not found")
	ErrRefreshTokenExpired  = errors.New("refresh token expired")
	ErrRefreshTokenRevoked  = errors.New("refresh token revoked")
	ErrUserNotFound         = errors.New("user not found")
	ErrOTPNotFound          = errors.New("otp not found")
)

// Manager 缓存管理器
// 统管所有缓存操作：本地缓存（热数据）+ Redis（分布式数据）
type Manager struct {
	// Hermes Service（获取应用/服务/域/用户数据）
	hermesSvc *hermes.Service
	userSvc   *hermes.UserService

	// 本地缓存（ristretto，用于热数据）
	domainCache      *ristretto.Cache[string, *models.DomainWithKey]
	applicationCache *ristretto.Cache[string, *models.ApplicationWithKey]
	serviceCache     *ristretto.Cache[string, *models.ServiceWithKey]
	relationCache    *ristretto.Cache[string, []models.ApplicationServiceRelation]
	appServiceCache  *ristretto.Cache[string, bool] // 复合 key 缓存：app_id:service_id -> bool
	userCache        *ristretto.Cache[string, *models.UserWithDecrypted]

	// 应用跨域配置缓存：app_id -> allowed_origins
	appOriginsCache *ristretto.Cache[string, []string]

	// 应用 IDP 配置缓存：app_id -> []*ApplicationIDPConfig
	appIDPConfigCache *ristretto.Cache[string, []*models.ApplicationIDPConfig]

	// Challenge 配置缓存：service_id:type -> *ServiceChallengeSetting
	challengeConfigCache *ristretto.Cache[string, *models.ServiceChallengeSetting]

	// 公钥缓存：client_id -> *KeyEntry
	pubKeyCache *ristretto.Cache[string, *KeyEntry]

	// Redis 客户端（用于分布式数据）
	redis pkgredis.Client
}

// NewManager 创建缓存管理器
func NewManager(hermesSvc *hermes.Service, userSvc *hermes.UserService, redis pkgredis.Client) *Manager {
	cm := &Manager{
		hermesSvc: hermesSvc,
		userSvc:   userSvc,
		redis:     redis,
	}

	// 创建本地缓存
	cm.initLocalCaches()

	// 创建公钥缓存
	cm.initPubKeyCache()

	return cm
}

// initLocalCaches 初始化本地缓存
func (cm *Manager) initLocalCaches() {
	// Domain cache
	domainCache, err := ristretto.NewCache(&ristretto.Config[string, *models.DomainWithKey]{
		NumCounters: config.GetCacheNumCounters("domain"),
		MaxCost:     config.GetCacheSize("domain"),
		BufferItems: config.GetCacheBufferItems("domain"),
	})
	if err != nil {
		logger.Errorf("[Manager] 创建 Domain 缓存失败: %v", err)
	} else {
		cm.domainCache = domainCache
	}

	// Application cache
	applicationCache, err := ristretto.NewCache(&ristretto.Config[string, *models.ApplicationWithKey]{
		NumCounters: config.GetCacheNumCounters("application"),
		MaxCost:     config.GetCacheSize("application"),
		BufferItems: config.GetCacheBufferItems("application"),
	})
	if err != nil {
		logger.Errorf("[Manager] 创建 Application 缓存失败: %v", err)
	} else {
		cm.applicationCache = applicationCache
	}

	// Service cache
	serviceCache, err := ristretto.NewCache(&ristretto.Config[string, *models.ServiceWithKey]{
		NumCounters: config.GetCacheNumCounters("service"),
		MaxCost:     config.GetCacheSize("service"),
		BufferItems: config.GetCacheBufferItems("service"),
	})
	if err != nil {
		logger.Errorf("[Manager] 创建 Service 缓存失败: %v", err)
	} else {
		cm.serviceCache = serviceCache
	}

	// ApplicationServiceRelation cache
	relationCache, err := ristretto.NewCache(&ristretto.Config[string, []models.ApplicationServiceRelation]{
		NumCounters: config.GetCacheNumCounters("application-service-relation"),
		MaxCost:     config.GetCacheSize("application-service-relation"),
		BufferItems: config.GetCacheBufferItems("application-service-relation"),
	})
	if err != nil {
		logger.Errorf("[Manager] 创建 Relation 缓存失败: %v", err)
	} else {
		cm.relationCache = relationCache
	}

	// App-Service 复合 key 缓存（用于快速查询 app_id + service_id）
	appServiceCache, err := ristretto.NewCache(&ristretto.Config[string, bool]{
		NumCounters: config.GetCacheNumCounters("app-service"),
		MaxCost:     config.GetCacheSize("app-service"),
		BufferItems: config.GetCacheBufferItems("app-service"),
	})
	if err != nil {
		logger.Errorf("[Manager] 创建 App-Service 缓存失败: %v", err)
	} else {
		cm.appServiceCache = appServiceCache
	}

	// User cache
	userCache, err := ristretto.NewCache(&ristretto.Config[string, *models.UserWithDecrypted]{
		NumCounters: config.GetCacheNumCounters("user"),
		MaxCost:     config.GetCacheSize("user"),
		BufferItems: config.GetCacheBufferItems("user"),
	})
	if err != nil {
		logger.Errorf("[Manager] 创建 User 缓存失败: %v", err)
	} else {
		cm.userCache = userCache
	}

	// App Origins cache（应用跨域配置）
	appOriginsCache, err := ristretto.NewCache(&ristretto.Config[string, []string]{
		NumCounters: config.GetCacheNumCounters("app-origins"),
		MaxCost:     config.GetCacheSize("app-origins"),
		BufferItems: config.GetCacheBufferItems("app-origins"),
	})
	if err != nil {
		logger.Errorf("[Manager] 创建 App Origins 缓存失败: %v", err)
	} else {
		cm.appOriginsCache = appOriginsCache
	}

	// App IDP Config cache（应用 IDP 配置）
	appIDPConfigCache, err := ristretto.NewCache(&ristretto.Config[string, []*models.ApplicationIDPConfig]{
		NumCounters: config.GetCacheNumCounters("app-idp-config"),
		MaxCost:     config.GetCacheSize("app-idp-config"),
		BufferItems: config.GetCacheBufferItems("app-idp-config"),
	})
	if err != nil {
		logger.Errorf("[Manager] 创建 App IDP Config 缓存失败: %v", err)
	} else {
		cm.appIDPConfigCache = appIDPConfigCache
	}

	// Challenge Config cache（服务 Challenge 配置）
	challengeConfigCache, err := ristretto.NewCache(&ristretto.Config[string, *models.ServiceChallengeSetting]{
		NumCounters: config.GetCacheNumCounters("challenge-config"),
		MaxCost:     config.GetCacheSize("challenge-config"),
		BufferItems: config.GetCacheBufferItems("challenge-config"),
	})
	if err != nil {
		logger.Errorf("[Manager] 创建 Challenge Config 缓存失败: %v", err)
	} else {
		cm.challengeConfigCache = challengeConfigCache
	}
}

// Close 关闭缓存
func (cm *Manager) Close() {
	if cm.domainCache != nil {
		cm.domainCache.Close()
	}
	if cm.applicationCache != nil {
		cm.applicationCache.Close()
	}
	if cm.serviceCache != nil {
		cm.serviceCache.Close()
	}
	if cm.relationCache != nil {
		cm.relationCache.Close()
	}
	if cm.appServiceCache != nil {
		cm.appServiceCache.Close()
	}
	if cm.userCache != nil {
		cm.userCache.Close()
	}
	if cm.appOriginsCache != nil {
		cm.appOriginsCache.Close()
	}
	if cm.appIDPConfigCache != nil {
		cm.appIDPConfigCache.Close()
	}
	if cm.pubKeyCache != nil {
		cm.pubKeyCache.Close()
	}
	if cm.challengeConfigCache != nil {
		cm.challengeConfigCache.Close()
	}
}
