package cache

import (
	"errors"

	"github.com/dgraph-io/ristretto/v2"

	"github.com/heliannuuthus/helios/aegis/config"
	"github.com/heliannuuthus/helios/aegis/internal/contract"
	"github.com/heliannuuthus/helios/pkg/logger"
	"github.com/heliannuuthus/helios/pkg/models"
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
	hermesSvc contract.HermesProvider
	userSvc   contract.UserProvider

	// 本地缓存（ristretto，用于热数据）
	domainCache      *ristretto.Cache[string, *DomainWithKey]
	applicationCache *ristretto.Cache[string, *ApplicationWithKey]
	serviceCache     *ristretto.Cache[string, *ServiceWithKey]
	relationCache    *ristretto.Cache[string, []models.ApplicationServiceRelation]
	userCache        *ristretto.Cache[string, *models.UserWithDecrypted]

	// 应用 IDP 配置缓存：app_id -> []*ApplicationIDPConfig
	appIDPConfigCache *ristretto.Cache[string, []*models.ApplicationIDPConfig]

	// Challenge 配置缓存：service_id:type -> *ServiceChallengeSetting
	challengeConfigCache *ristretto.Cache[string, *models.ServiceChallengeSetting]

	// SSO 密钥缓存（派生后的密钥，走 ristretto TTL 自动过期）
	ssoKeyCache *ristretto.Cache[string, *Keys]

	// Redis 客户端（用于分布式数据）
	redis pkgredis.Client
}

func newCache[V any](name string, numCounters, maxCost int64, bufferItems int64) *ristretto.Cache[string, V] {
	c, err := ristretto.NewCache(&ristretto.Config[string, V]{
		NumCounters: numCounters,
		MaxCost:     maxCost,
		BufferItems: bufferItems,
	})
	if err != nil {
		logger.Fatalf("[Manager] 创建 %s 缓存失败: %v", name, err)
	}
	return c
}

func newConfiguredCache[V any](name string) *ristretto.Cache[string, V] {
	return newCache[V](name, config.GetCacheNumCounters(name), config.GetCacheSize(name), config.GetCacheBufferItems(name))
}

func NewManager(hermesSvc contract.HermesProvider, userSvc contract.UserProvider, redis pkgredis.Client) *Manager {
	return &Manager{
		hermesSvc:            hermesSvc,
		userSvc:              userSvc,
		redis:                redis,
		domainCache:          newConfiguredCache[*DomainWithKey]("domain"),
		applicationCache:     newConfiguredCache[*ApplicationWithKey]("application"),
		serviceCache:         newConfiguredCache[*ServiceWithKey]("service"),
		relationCache:        newConfiguredCache[[]models.ApplicationServiceRelation]("application-service-relation"),
		userCache:            newConfiguredCache[*models.UserWithDecrypted]("user"),
		appIDPConfigCache:    newConfiguredCache[[]*models.ApplicationIDPConfig]("app-idp-config"),
		challengeConfigCache: newConfiguredCache[*models.ServiceChallengeSetting]("challenge-config"),
		ssoKeyCache:          newCache[*Keys]("sso", 10, 1, 64),
	}
}

func (cm *Manager) Close() {
	cm.domainCache.Close()
	cm.applicationCache.Close()
	cm.serviceCache.Close()
	cm.relationCache.Close()
	cm.userCache.Close()
	cm.appIDPConfigCache.Close()
	cm.challengeConfigCache.Close()
	cm.ssoKeyCache.Close()
}
