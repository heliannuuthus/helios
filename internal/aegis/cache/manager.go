package cache

import (
	"errors"

	"github.com/dgraph-io/ristretto/v2"

	"github.com/heliannuuthus/helios/internal/config"
	"github.com/heliannuuthus/helios/internal/hermes"
	"github.com/heliannuuthus/helios/internal/hermes/models"
	"github.com/heliannuuthus/helios/pkg/logger"
	pkgstore "github.com/heliannuuthus/helios/pkg/store"
)

// 错误定义
var (
	ErrAuthFlowNotFound     = errors.New("auth flow not found")
	ErrAuthFlowExpired      = errors.New("auth flow expired")
	ErrAuthCodeNotFound     = errors.New("authorization code not found")
	ErrAuthCodeExpired      = errors.New("authorization code expired")
	ErrAuthCodeUsed         = errors.New("authorization code already used")
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

	// Redis 客户端（用于分布式数据）
	redis pkgstore.RedisClient
}

// ManagerConfig 配置
type ManagerConfig struct {
	HermesSvc *hermes.Service
	UserSvc   *hermes.UserService
	Redis     pkgstore.RedisClient
}

// NewManager 创建缓存管理器
func NewManager(cfg *ManagerConfig) *Manager {
	cm := &Manager{
		hermesSvc: cfg.HermesSvc,
		userSvc:   cfg.UserSvc,
		redis:     cfg.Redis,
	}

	// 创建本地缓存
	cm.initLocalCaches()

	return cm
}

// initLocalCaches 初始化本地缓存
func (cm *Manager) initLocalCaches() {
	// Domain cache
	domainCache, err := ristretto.NewCache(&ristretto.Config[string, *models.DomainWithKey]{
		NumCounters: config.GetAegisCacheNumCounters("domain"),
		MaxCost:     config.GetAegisCacheSize("domain"),
		BufferItems: config.GetAegisCacheBufferItems("domain"),
	})
	if err != nil {
		logger.Errorf("[Manager] 创建 Domain 缓存失败: %v", err)
	} else {
		cm.domainCache = domainCache
	}

	// Application cache
	applicationCache, err := ristretto.NewCache(&ristretto.Config[string, *models.ApplicationWithKey]{
		NumCounters: config.GetAegisCacheNumCounters("application"),
		MaxCost:     config.GetAegisCacheSize("application"),
		BufferItems: config.GetAegisCacheBufferItems("application"),
	})
	if err != nil {
		logger.Errorf("[Manager] 创建 Application 缓存失败: %v", err)
	} else {
		cm.applicationCache = applicationCache
	}

	// Service cache
	serviceCache, err := ristretto.NewCache(&ristretto.Config[string, *models.ServiceWithKey]{
		NumCounters: config.GetAegisCacheNumCounters("service"),
		MaxCost:     config.GetAegisCacheSize("service"),
		BufferItems: config.GetAegisCacheBufferItems("service"),
	})
	if err != nil {
		logger.Errorf("[Manager] 创建 Service 缓存失败: %v", err)
	} else {
		cm.serviceCache = serviceCache
	}

	// ApplicationServiceRelation cache
	relationCache, err := ristretto.NewCache(&ristretto.Config[string, []models.ApplicationServiceRelation]{
		NumCounters: config.GetAegisCacheNumCounters("application-service-relation"),
		MaxCost:     config.GetAegisCacheSize("application-service-relation"),
		BufferItems: config.GetAegisCacheBufferItems("application-service-relation"),
	})
	if err != nil {
		logger.Errorf("[Manager] 创建 Relation 缓存失败: %v", err)
	} else {
		cm.relationCache = relationCache
	}

	// App-Service 复合 key 缓存（用于快速查询 app_id + service_id）
	appServiceCache, err := ristretto.NewCache(&ristretto.Config[string, bool]{
		NumCounters: config.GetAegisCacheNumCounters("app-service"),
		MaxCost:     config.GetAegisCacheSize("app-service"),
		BufferItems: config.GetAegisCacheBufferItems("app-service"),
	})
	if err != nil {
		logger.Errorf("[Manager] 创建 App-Service 缓存失败: %v", err)
	} else {
		cm.appServiceCache = appServiceCache
	}

	// User cache
	userCache, err := ristretto.NewCache(&ristretto.Config[string, *models.UserWithDecrypted]{
		NumCounters: config.GetAegisCacheNumCounters("user"),
		MaxCost:     config.GetAegisCacheSize("user"),
		BufferItems: config.GetAegisCacheBufferItems("user"),
	})
	if err != nil {
		logger.Errorf("[Manager] 创建 User 缓存失败: %v", err)
	} else {
		cm.userCache = userCache
	}

	// App Origins cache（应用跨域配置）
	appOriginsCache, err := ristretto.NewCache(&ristretto.Config[string, []string]{
		NumCounters: config.GetAegisCacheNumCounters("app-origins"),
		MaxCost:     config.GetAegisCacheSize("app-origins"),
		BufferItems: config.GetAegisCacheBufferItems("app-origins"),
	})
	if err != nil {
		logger.Errorf("[Manager] 创建 App Origins 缓存失败: %v", err)
	} else {
		cm.appOriginsCache = appOriginsCache
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
}

