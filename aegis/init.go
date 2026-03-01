package aegis

import (
	"context"
	"fmt"
	"time"

	"github.com/heliannuuthus/helios/aegis/config"
	"github.com/heliannuuthus/helios/aegis/internal/authenticate"
	"github.com/heliannuuthus/helios/aegis/internal/authenticator"
	"github.com/heliannuuthus/helios/aegis/internal/authenticator/captcha"
	"github.com/heliannuuthus/helios/aegis/internal/authenticator/factor"
	"github.com/heliannuuthus/helios/aegis/internal/authenticator/idp"
	"github.com/heliannuuthus/helios/aegis/internal/authenticator/idp/alipay"
	"github.com/heliannuuthus/helios/aegis/internal/authenticator/idp/github"
	"github.com/heliannuuthus/helios/aegis/internal/authenticator/idp/google"
	"github.com/heliannuuthus/helios/aegis/internal/authenticator/idp/passkey"
	"github.com/heliannuuthus/helios/aegis/internal/authenticator/idp/staff"
	"github.com/heliannuuthus/helios/aegis/internal/authenticator/idp/tt"
	idpuser "github.com/heliannuuthus/helios/aegis/internal/authenticator/idp/user"
	"github.com/heliannuuthus/helios/aegis/internal/authenticator/idp/wechat"
	"github.com/heliannuuthus/helios/aegis/internal/authenticator/totp"
	"github.com/heliannuuthus/helios/aegis/internal/authenticator/vchan"
	"github.com/heliannuuthus/helios/aegis/internal/authenticator/webauthn"
	"github.com/heliannuuthus/helios/aegis/internal/authorize"
	"github.com/heliannuuthus/helios/aegis/internal/cache"
	"github.com/heliannuuthus/helios/aegis/internal/challenge"
	"github.com/heliannuuthus/helios/aegis/internal/token"
	"github.com/heliannuuthus/helios/aegis/internal/user"
	"github.com/heliannuuthus/helios/hermes"
	"github.com/heliannuuthus/helios/pkg/accessctl"
	"github.com/heliannuuthus/helios/pkg/aegis/key"
	"github.com/heliannuuthus/helios/pkg/async"
	"github.com/heliannuuthus/helios/pkg/logger"
	"github.com/heliannuuthus/helios/pkg/mail"
	pkgredis "github.com/heliannuuthus/helios/pkg/redis"
	"github.com/heliannuuthus/helios/pkg/throttle"
)

// Initialize 初始化 Auth 模块，返回 Handler
func Initialize(hermesSvc *hermes.Service, userSvc *hermes.UserService, credentialSvc *hermes.CredentialService) (*Handler, error) {
	// 1. 初始化 Redis
	redisURL := getRedisURL()
	redis, err := pkgredis.NewClient(redisURL)
	if err != nil {
		return nil, err
	}
	logger.Infof("[Auth] Redis 连接成功: %s", redisURL)

	// 2. 初始化 Cache Manager
	cacheManager := cache.NewManager(hermesSvc, userSvc, redis)

	// 3. 初始化 KeyStore
	watcher := key.NewSimpleWatcher()

	ssoMasterKeyFetcher := func() ([][]byte, error) {
		masterKey, err := config.GetSSOMasterKey()
		if err != nil {
			return nil, fmt.Errorf("get sso master key: %w", err)
		}
		if masterKey == nil {
			return nil, fmt.Errorf("sso master key not configured")
		}
		return [][]byte{masterKey}, nil
	}

	// 域密钥：clientID → domain.Main（id="aegis" 时返回 SSO master key）
	domainKeyStore := key.NewNamedStore("domain", key.FetcherFunc(func(ctx context.Context, clientID string) ([][]byte, error) {
		if clientID == token.SSOIssuer {
			return ssoMasterKeyFetcher()
		}
		app, err := cacheManager.GetApplication(ctx, clientID)
		if err != nil {
			return nil, fmt.Errorf("get application: %w", err)
		}
		domain, err := cacheManager.GetDomain(ctx, app.DomainID)
		if err != nil {
			return nil, fmt.Errorf("get domain: %w", err)
		}
		return [][]byte{domain.Main}, nil
	}), watcher)

	// 服务密钥：audience → service.Key（id="aegis" 时返回 SSO master key）
	serviceKeyStore := key.NewNamedStore("service", key.FetcherFunc(func(ctx context.Context, audience string) ([][]byte, error) {
		if audience == token.SSOAudience {
			return ssoMasterKeyFetcher()
		}
		svc, err := cacheManager.GetService(ctx, audience)
		if err != nil {
			return nil, fmt.Errorf("get service: %w", err)
		}
		return [][]byte{svc.Key}, nil
	}), watcher)

	// 应用密钥：clientID → app.Key
	appKeyStore := key.NewNamedStore("app", key.FetcherFunc(func(ctx context.Context, clientID string) ([][]byte, error) {
		app, err := cacheManager.GetApplication(ctx, clientID)
		if err != nil {
			return nil, fmt.Errorf("get application: %w", err)
		}
		return [][]byte{app.Key}, nil
	}), watcher)

	// 4. 初始化 Token Service
	tokenSvc := token.NewService(cacheManager, domainKeyStore, serviceKeyStore, appKeyStore)
	logger.Info("[Auth] Token Service 初始化完成")

	// 4. 初始化邮件发送器
	emailSender := initMailSender()
	if emailSender != nil {
		logger.Info("[Auth] 邮件发送器初始化完成")
	}

	// 5. 初始化底层 Provider
	webauthnSvc, captchaVerifier, totpVerifier := initProviders(credentialSvc, cacheManager)

	// 6. 初始化访问控制管理器
	throttler := throttle.NewThrottler(redis)
	ac := accessctl.NewManager(throttler)
	logger.Info("[Auth] 访问控制管理器初始化完成")

	// 7. 初始化全局 Registry（胶水层 Authenticator 统一注册）
	registry := initRegistry(userSvc, cacheManager, emailSender, webauthnSvc, captchaVerifier, totpVerifier, ac, tokenSvc)

	// 8. 初始化异步任务池
	pool, err := async.NewPool(64)
	if err != nil {
		return nil, err
	}

	// 9. 初始化 User Service
	userService := user.NewService(cacheManager, userSvc)

	// 10. 初始化 Authenticate Service
	authenticateSvc := authenticate.NewService(cacheManager, ac)

	// 11. 初始化 Authorize Service
	authorizeSvc := authorize.NewService(cacheManager, userService, tokenSvc, pool, 5*time.Minute)

	// 12. 初始化 Challenge Service（直接复用 Registry，不再重复构建 Provider）
	challengeSvc := challenge.NewService(cacheManager, registry)

	// 13. 创建 MFA Service 门面
	mfaSvc := NewMFAService(webauthnSvc)

	// 14. 创建 Handler
	handler := NewHandler(authenticateSvc, authorizeSvc, challengeSvc, userService, cacheManager, tokenSvc, mfaSvc, pool)

	logger.Info("[Auth] 模块初始化完成")
	return handler, nil
}

// initProviders 初始化底层 Provider（WebAuthn、Captcha、TOTP）
func initProviders(credentialSvc *hermes.CredentialService, cacheManager *cache.Manager) (*webauthn.Service, captcha.Verifier, factor.TOTPVerifier) {
	// WebAuthn
	var webauthnSvc *webauthn.Service
	if svc, err := webauthn.NewService(cacheManager); err != nil {
		logger.Warnf("[Auth] WebAuthn 初始化失败: %v", err)
	} else {
		webauthnSvc = svc
		logger.Info("[Auth] WebAuthn 初始化完成")
	}

	// Captcha
	captchaVerifier := initCaptchaVerifier()
	if captchaVerifier != nil {
		logger.Infof("[Auth] Captcha 验证器初始化完成: provider=%s", captchaVerifier.GetProvider())
	}

	// TOTP
	var totpVerifier factor.TOTPVerifier
	if credentialSvc != nil {
		totpVerifier = totp.NewVerifier(credentialSvc)
		logger.Info("[Auth] TOTP 验证器初始化完成")
	}

	return webauthnSvc, captchaVerifier, totpVerifier
}

// initRegistry 初始化全局 Registry（注册胶水层 Authenticator）
func initRegistry(userSvc *hermes.UserService, cacheManager *cache.Manager, emailSender *mail.Sender, webauthnSvc *webauthn.Service, captchaVerifier captcha.Verifier, totpVerifier factor.TOTPVerifier, ac *accessctl.Manager, tokenVerifier authenticate.ChallengeTokenVerifier) *authenticator.Registry {
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
		registerIDP(idpuser.NewProvider(userSvc))
		registerIDP(staff.NewProvider(userSvc))
	}

	if webauthnSvc != nil {
		registerIDP(passkey.NewProvider(webauthnSvc))
		logger.Info("[Auth] Passkey IDP 注册完成")
	}

	// ==================== VChan Authenticators ====================

	if captchaVerifier != nil {
		registry.Register(authenticate.NewVChanAuthenticator(vchan.NewCaptchaProvider(captchaVerifier)))
	}

	// ==================== Factor Authenticators ====================

	if emailSender != nil {
		registry.Register(authenticate.NewFactorAuthenticator(factor.NewEmailOTPProvider(emailSender, cacheManager), ac, tokenVerifier))
	}

	if totpVerifier != nil {
		registry.Register(authenticate.NewFactorAuthenticator(factor.NewTOTPProvider(totpVerifier), ac, tokenVerifier))
	}

	if webauthnSvc != nil {
		registry.Register(authenticate.NewFactorAuthenticator(factor.NewWebAuthnProvider(webauthnSvc), ac, tokenVerifier))
	}

	logger.Infof("[Auth] Registry 初始化完成: %v", registry.Summary())
	return registry
}

// getRedisURL 获取 Redis URL
func getRedisURL() string {
	cfg := config.Cfg()
	url := cfg.GetString("redis.url")
	if url == "" {
		url = "redis://localhost:6379/0"
	}
	return url
}

// initCaptchaVerifier 初始化 Captcha 验证器
func initCaptchaVerifier() captcha.Verifier {
	cfg := config.Cfg()

	siteKey := cfg.GetString("vchan.captcha.turnstile.app_id")
	secretKey := cfg.GetString("vchan.captcha.turnstile.secret")
	if siteKey == "" || secretKey == "" {
		logger.Warn("[Auth] Turnstile 配置不完整，跳过初始化")
		return nil
	}
	return captcha.NewTurnstileVerifier(siteKey, secretKey)
}

// initMailSender 初始化邮件发送器
func initMailSender() *mail.Sender {
	cfg := config.GetMailConfig()
	if cfg.Username == "" || cfg.Password == "" {
		logger.Warn("[Auth] 邮件配置不完整（缺少 username 或 password），跳过初始化")
		return nil
	}

	sender, err := mail.NewSender(&mail.SenderConfig{
		Host:     cfg.Host,
		Port:     cfg.Port,
		Username: cfg.Username,
		Password: cfg.Password,
		UseSSL:   cfg.UseSSL,
	})
	if err != nil {
		logger.Errorf("[Auth] 创建邮件发送器失败: %v", err)
		return nil
	}

	logger.Infof("[Auth] 邮件连接池初始化成功: %s:%d", cfg.Host, cfg.Port)
	return sender
}
