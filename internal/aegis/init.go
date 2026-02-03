package aegis

import (
	"context"
	"time"

	"github.com/heliannuuthus/helios/internal/aegis/authenticate"
	"github.com/heliannuuthus/helios/internal/aegis/authorize"
	"github.com/heliannuuthus/helios/internal/aegis/cache"
	"github.com/heliannuuthus/helios/internal/aegis/captcha"
	"github.com/heliannuuthus/helios/internal/aegis/challenge"
	"github.com/heliannuuthus/helios/internal/aegis/idp"
	"github.com/heliannuuthus/helios/internal/aegis/idp/alipay"
	"github.com/heliannuuthus/helios/internal/aegis/idp/github"
	"github.com/heliannuuthus/helios/internal/aegis/idp/google"
	"github.com/heliannuuthus/helios/internal/aegis/idp/tt"
	"github.com/heliannuuthus/helios/internal/aegis/idp/wechat"
	"github.com/heliannuuthus/helios/internal/aegis/mail"
	"github.com/heliannuuthus/helios/internal/aegis/token"
	"github.com/heliannuuthus/helios/internal/aegis/webauthn"
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

	// 5. 初始化邮件发送器（如果启用）
	var emailSender *mail.Sender
	if config.IsMailEnabled() {
		emailSender = initMailSender()
		if emailSender != nil {
			logger.Info("[Auth] 邮件发送器初始化完成")
		}
	}

	// 6. 初始化 Authenticate Service
	authenticateSvc := authenticate.NewService(&authenticate.ServiceConfig{
		Cache:       cacheManager,
		IDPRegistry: idpRegistry,
		EmailSender: emailSender,
	})

	// 7. 初始化 Authorize Service
	authorizeSvc := authorize.NewService(&authorize.ServiceConfig{
		Cache:             cacheManager,
		TokenSvc:          tokenSvc,
		DefaultAccessTTL:  getAccessTokenTTL(),
		DefaultRefreshTTL: getRefreshTokenTTL(),
		AuthCodeTTL:       5 * time.Minute,
	})

	// 8. 初始化 Captcha Verifier（如果启用）
	var captchaVerifier captcha.Verifier
	if isCaptchaEnabled() {
		captchaVerifier = initCaptchaVerifier()
		if captchaVerifier != nil {
			logger.Infof("[Auth] Captcha 验证器初始化完成: provider=%s", captchaVerifier.GetProvider())
		}
	}

	// 9. 初始化 Challenge Service
	challengeSvc := challenge.NewService(&challenge.ServiceConfig{
		Cache:        cacheManager,
		Captcha:      captchaVerifier,
		EmailSender:  emailSender,
		TOTPVerifier: nil, // TODO: 可选的 TOTP 验证器
	})

	// 10. 创建 Handler
	handler := NewHandler(&HandlerConfig{
		AuthenticateSvc: authenticateSvc,
		AuthorizeSvc:    authorizeSvc,
		ChallengeSvc:    challengeSvc,
		Cache:           cacheManager,
		TokenSvc:        tokenSvc,
	})

	// 11. 初始化 WebAuthn Service（如果启用）
	if webauthn.IsEnabled() {
		webauthnSvc, err := webauthn.NewService(cacheManager)
		if err != nil {
			logger.Warnf("[Auth] WebAuthn 初始化失败: %v", err)
		} else {
			handler.SetWebAuthnService(webauthnSvc)
			logger.Info("[Auth] WebAuthn 初始化完成")
		}
	}

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
	cfg := config.Aegis()
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
	cfg := config.Aegis()
	expiresIn := cfg.GetInt("aegis.expires-in")
	if expiresIn == 0 {
		expiresIn = 7200 // 默认 2 小时
	}
	return time.Duration(expiresIn) * time.Second
}

// getRefreshTokenTTL 获取 refresh_token 过期时间
func getRefreshTokenTTL() time.Duration {
	cfg := config.Aegis()
	days := cfg.GetInt("aegis.refresh-expires-in")
	if days == 0 {
		days = 365 // 默认 1 年
	}
	return time.Duration(days) * 24 * time.Hour
}

// isCaptchaEnabled 检查是否启用 Captcha
func isCaptchaEnabled() bool {
	cfg := config.Aegis()
	return cfg.GetBool("captcha.enabled")
}

// initCaptchaVerifier 初始化 Captcha 验证器
func initCaptchaVerifier() captcha.Verifier {
	cfg := config.Aegis()
	provider := cfg.GetString("captcha.provider")

	switch provider {
	case captcha.ProviderTurnstile, "":
		siteKey := cfg.GetString("captcha.site-key")
		secretKey := cfg.GetString("captcha.secret-key")
		if siteKey == "" || secretKey == "" {
			logger.Warn("[Auth] Turnstile 配置不完整，跳过初始化")
			return nil
		}
		return captcha.NewTurnstileVerifier(&captcha.TurnstileConfig{
			SiteKey:   siteKey,
			SecretKey: secretKey,
		})
	default:
		logger.Warnf("[Auth] 不支持的 Captcha 提供商: %s", provider)
		return nil
	}
}

// initMailSender 初始化邮件发送器
func initMailSender() *mail.Sender {
	cfg := config.GetMailConfig()
	if cfg.Username == "" || cfg.Password == "" {
		logger.Warn("[Auth] 邮件配置不完整（缺少 username 或 password），跳过初始化")
		return nil
	}

	sender := mail.NewSender(&mail.SenderConfig{
		Host:     cfg.Host,
		Port:     cfg.Port,
		Username: cfg.Username,
		Password: cfg.Password,
		UseSSL:   cfg.UseSSL,
	})

	// 验证 SMTP 连接
	if err := sender.Verify(context.Background()); err != nil {
		logger.Warnf("[Auth] 邮件服务器连接验证失败: %v", err)
		// 仍然返回 sender，允许后续重试
	} else {
		logger.Infof("[Auth] 邮件服务器连接验证成功: %s:%d", cfg.Host, cfg.Port)
	}

	return sender
}
