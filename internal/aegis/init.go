package aegis

import (
	"context"
	"time"

	"github.com/heliannuuthus/helios/internal/aegis/authenticate"
	"github.com/heliannuuthus/helios/internal/aegis/authenticator"
	"github.com/heliannuuthus/helios/internal/aegis/authenticator/captcha"
	"github.com/heliannuuthus/helios/internal/aegis/authenticator/idp"
	"github.com/heliannuuthus/helios/internal/aegis/authenticator/idp/alipay"
	"github.com/heliannuuthus/helios/internal/aegis/authenticator/idp/github"
	"github.com/heliannuuthus/helios/internal/aegis/authenticator/idp/google"
	"github.com/heliannuuthus/helios/internal/aegis/authenticator/idp/passkey"
	"github.com/heliannuuthus/helios/internal/aegis/authenticator/idp/system"
	"github.com/heliannuuthus/helios/internal/aegis/authenticator/idp/tt"
	"github.com/heliannuuthus/helios/internal/aegis/authenticator/idp/wechat"
	"github.com/heliannuuthus/helios/internal/aegis/authenticator/mfa"
	"github.com/heliannuuthus/helios/internal/aegis/authenticator/totp"
	"github.com/heliannuuthus/helios/internal/aegis/authenticator/webauthn"
	"github.com/heliannuuthus/helios/internal/aegis/authorize"
	"github.com/heliannuuthus/helios/internal/aegis/cache"
	"github.com/heliannuuthus/helios/internal/aegis/challenge"
	"github.com/heliannuuthus/helios/internal/aegis/token"
	"github.com/heliannuuthus/helios/internal/aegis/user"
	"github.com/heliannuuthus/helios/internal/config"
	"github.com/heliannuuthus/helios/internal/hermes"
	"github.com/heliannuuthus/helios/pkg/logger"
	"github.com/heliannuuthus/helios/pkg/mail"
	pkgstore "github.com/heliannuuthus/helios/pkg/store"
)

// Initialize 初始化 Auth 模块，返回 Handler
func Initialize(hermesSvc *hermes.Service, userSvc *hermes.UserService, credentialSvc *hermes.CredentialService) (*Handler, error) {
	// 1. 初始化 Redis
	redisCfg := getRedisConfig()
	redis, err := pkgstore.NewGoRedisClient(redisCfg)
	if err != nil {
		return nil, err
	}
	logger.Infof("[Auth] Redis 连接成功: %s:%d", redisCfg.Host, redisCfg.Port)

	// 2. 初始化 Cache Manager
	cacheManager := cache.NewManager(hermesSvc, userSvc, redis)

	// 3. 初始化 Token Service
	tokenSvc := token.NewService(cacheManager)

	// 4. 初始化邮件发送器（如果启用）
	var emailSender *mail.Sender
	if config.IsMailEnabled() {
		emailSender = initMailSender()
		if emailSender != nil {
			logger.Info("[Auth] 邮件发送器初始化完成")
		}
	}

	// 5. 初始化底层 Provider
	webauthnSvc, captchaVerifier, totpVerifier := initProviders(credentialSvc, cacheManager)

	// 6. 初始化全局 Registry（胶水层 Authenticator 统一注册）
	initRegistry(userSvc, cacheManager, emailSender, webauthnSvc, captchaVerifier, totpVerifier)

	// 7. 初始化 User Service
	userService := user.NewService(cacheManager, userSvc)

	// 8. 初始化 Authenticate Service
	authenticateSvc := authenticate.NewService(cacheManager)

	// 9. 初始化 Authorize Service
	authorizeSvc := authorize.NewService(&authorize.ServiceConfig{
		Cache:             cacheManager,
		UserSvc:           userService,
		TokenSvc:          tokenSvc,
		DefaultAccessTTL:  getAccessTokenTTL(),
		DefaultRefreshTTL: getRefreshTokenTTL(),
		AuthCodeTTL:       5 * time.Minute,
	})

	// 10. 初始化 Challenge Service
	challengeProviders := buildChallengeProviders(cacheManager, emailSender, webauthnSvc, totpVerifier)
	challengeSvc := challenge.NewService(cacheManager, captchaVerifier, challengeProviders)

	// 11. 创建 Handler
	handler := NewHandler(authenticateSvc, authorizeSvc, challengeSvc, userService, cacheManager, tokenSvc, webauthnSvc)

	logger.Info("[Auth] 模块初始化完成")
	return handler, nil
}

// initProviders 初始化底层 Provider（WebAuthn、Captcha、TOTP）
func initProviders(credentialSvc *hermes.CredentialService, cacheManager *cache.Manager) (*webauthn.Service, captcha.Verifier, mfa.TOTPVerifier) {
	// WebAuthn
	var webauthnSvc *webauthn.Service
	if webauthn.IsEnabled() {
		var err error
		webauthnSvc, err = webauthn.NewService(cacheManager)
		if err != nil {
			logger.Warnf("[Auth] WebAuthn 初始化失败: %v", err)
		} else {
			logger.Info("[Auth] WebAuthn 初始化完成")
		}
	}

	// Captcha
	var captchaVerifier captcha.Verifier
	if isCaptchaEnabled() {
		captchaVerifier = initCaptchaVerifier()
		if captchaVerifier != nil {
			logger.Infof("[Auth] Captcha 验证器初始化完成: provider=%s", captchaVerifier.GetProvider())
		}
	}

	// TOTP
	var totpVerifier mfa.TOTPVerifier
	if credentialSvc != nil {
		totpVerifier = totp.NewVerifier(credentialSvc)
		logger.Info("[Auth] TOTP 验证器初始化完成")
	}

	return webauthnSvc, captchaVerifier, totpVerifier
}

// initRegistry 初始化全局 Registry（注册胶水层 Authenticator）
func initRegistry(userSvc *hermes.UserService, cacheManager *cache.Manager, emailSender *mail.Sender, webauthnSvc *webauthn.Service, captchaVerifier captcha.Verifier, totpVerifier mfa.TOTPVerifier) {
	registry := authenticator.NewRegistry()

	// ==================== IDP Authenticators ====================

	registerIDP := func(p idp.Provider) {
		registry.Register(authenticate.NewIDPAuthenticator(p))
	}

	registerIDP(wechat.NewMPProvider())
	registerIDP(tt.NewMPProvider())
	registerIDP(alipay.NewMPProvider())
	registerIDP(github.NewProvider())
	registerIDP(google.NewProvider())

	if userSvc != nil {
		registerIDP(system.NewUserProvider(userSvc))
		registerIDP(system.NewOperProvider(userSvc))
	}

	if webauthnSvc != nil {
		registerIDP(passkey.NewProvider(webauthnSvc))
		logger.Info("[Auth] Passkey IDP 注册完成")
	}

	// ==================== VChan Authenticators ====================

	if captchaVerifier != nil {
		registry.Register(authenticate.NewVChanAuthenticator(captchaVerifier))
	}

	// ==================== MFA Authenticators ====================

	aegisCfg := config.Aegis()

	// Email OTP
	if aegisCfg.GetBool("mfa.email-otp.enabled") && emailSender != nil {
		registry.Register(authenticate.NewMFAAuthenticator(mfa.NewEmailOTPProvider(emailSender, cacheManager)))
	}

	// TOTP
	if aegisCfg.GetBool("mfa.totp.enabled") && totpVerifier != nil {
		registry.Register(authenticate.NewMFAAuthenticator(mfa.NewTOTPProvider(totpVerifier)))
	}

	// WebAuthn MFA
	if aegisCfg.GetBool("mfa.webauthn.enabled") && webauthnSvc != nil {
		registry.Register(authenticate.NewMFAAuthenticator(mfa.NewWebAuthnProvider(webauthnSvc)))
	}

	logger.Infof("[Auth] Registry 初始化完成: %v", registry.Summary())
}

// buildChallengeProviders 构建 Challenge 可用的 MFA provider 列表
func buildChallengeProviders(cacheManager *cache.Manager, emailSender *mail.Sender, webauthnSvc *webauthn.Service, totpVerifier mfa.TOTPVerifier) []mfa.Provider {
	var providers []mfa.Provider

	if emailSender != nil {
		providers = append(providers, mfa.NewEmailOTPProvider(emailSender, cacheManager))
	}
	if totpVerifier != nil {
		providers = append(providers, mfa.NewTOTPProvider(totpVerifier))
	}
	if webauthnSvc != nil {
		providers = append(providers, mfa.NewWebAuthnProvider(webauthnSvc))
	}

	return providers
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
