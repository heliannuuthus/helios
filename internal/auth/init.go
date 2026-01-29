package auth

import (
	"time"

	"github.com/heliannuuthus/helios/internal/auth/authenticate"
	"github.com/heliannuuthus/helios/internal/auth/authorize"
	"github.com/heliannuuthus/helios/internal/auth/cache"
	"github.com/heliannuuthus/helios/internal/auth/idp"
	"github.com/heliannuuthus/helios/internal/auth/idp/alipay"
	"github.com/heliannuuthus/helios/internal/auth/idp/github"
	"github.com/heliannuuthus/helios/internal/auth/idp/google"
	"github.com/heliannuuthus/helios/internal/auth/idp/tt"
	"github.com/heliannuuthus/helios/internal/auth/idp/wechat"
	"github.com/heliannuuthus/helios/internal/auth/token"
	"github.com/heliannuuthus/helios/internal/config"
	"github.com/heliannuuthus/helios/internal/hermes"
	"github.com/heliannuuthus/helios/pkg/logger"
	pkgstore "github.com/heliannuuthus/helios/pkg/store"
)

// InitConfig 初始化配置
type InitConfig struct {
	HermesSvc *hermes.Service
	UserSvc   *hermes.UserService
}

// Initialize 初始化 Auth 模块，返回 Handler
func Initialize(cfg *InitConfig) (*Handler, error) {
	// 1. 初始化 Redis
	redisCfg := getRedisConfig()
	redis, err := pkgstore.NewGoRedisClient(redisCfg)
	if err != nil {
		return nil, err
	}
	logger.Infof("[Auth] Redis 连接成功: %s:%d", redisCfg.Host, redisCfg.Port)

	// 2. 初始化 Cache Manager
	cacheManager := cache.NewManager(&cache.ManagerConfig{
		HermesSvc: cfg.HermesSvc,
		UserSvc:   cfg.UserSvc,
		Redis:     redis,
	})

	// 3. 初始化 Token Service
	tokenSvc := token.NewService(cacheManager)

	// 4. 初始化 IDP Registry
	idpRegistry := initIDPRegistry()

	// 5. 初始化 Authenticate Service
	authenticateSvc := authenticate.NewService(&authenticate.ServiceConfig{
		Cache:       cacheManager,
		IDPRegistry: idpRegistry,
		EmailSender: nil, // TODO: 可选的邮件发送器
	})

	// 6. 初始化 Authorize Service
	authorizeSvc := authorize.NewService(&authorize.ServiceConfig{
		Cache:             cacheManager,
		TokenSvc:          tokenSvc,
		DefaultAccessTTL:  getAccessTokenTTL(),
		DefaultRefreshTTL: getRefreshTokenTTL(),
		AuthCodeTTL:       5 * time.Minute,
	})

	// 7. 创建 Handler
	handler := NewHandler(&HandlerConfig{
		AuthenticateSvc: authenticateSvc,
		AuthorizeSvc:    authorizeSvc,
		Cache:           cacheManager,
	})

	logger.Info("[Auth] 模块初始化完成")
	return handler, nil
}

// initIDPRegistry 初始化 IDP 注册表
func initIDPRegistry() *idp.Registry {
	registry := idp.NewRegistry()

	// 注册微信小程序
	registry.Register(wechat.NewMPProvider())

	// 注册抖音小程序
	registry.Register(tt.NewMPProvider())

	// 注册支付宝小程序
	registry.Register(alipay.NewMPProvider())

	// 注册 GitHub
	registry.Register(github.NewProvider())

	// 注册 Google
	registry.Register(google.NewProvider())

	logger.Infof("[Auth] IDP 注册完成: %v", registry.List())
	return registry
}

// getRedisConfig 获取 Redis 配置
func getRedisConfig() *pkgstore.GoRedisConfig {
	cfg := config.Auth()
	host := cfg.GetString("redis.host")
	if host == "" {
		host = "localhost"
	}
	port := cfg.GetInt("redis.port")
	if port == 0 {
		port = 6379
	}

	return &pkgstore.GoRedisConfig{
		Host:     host,
		Port:     port,
		Password: cfg.GetString("redis.password"),
		DB:       cfg.GetInt("redis.db"),
	}
}

// getAccessTokenTTL 获取 access_token 过期时间
func getAccessTokenTTL() time.Duration {
	cfg := config.Auth()
	expiresIn := cfg.GetInt("auth.expires-in")
	if expiresIn == 0 {
		expiresIn = 7200 // 默认 2 小时
	}
	return time.Duration(expiresIn) * time.Second
}

// getRefreshTokenTTL 获取 refresh_token 过期时间
func getRefreshTokenTTL() time.Duration {
	cfg := config.Auth()
	days := cfg.GetInt("auth.refresh-expires-in")
	if days == 0 {
		days = 365 // 默认 1 年
	}
	return time.Duration(days) * 24 * time.Hour
}
