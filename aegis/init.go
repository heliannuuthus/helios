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
	redisURL := getRedisURL()
	redis, err := pkgredis.NewClient(redisURL)
	if err != nil {
		return nil, err
	}
	logger.Infof("[Auth] Redis 连接成功: %s", redisURL)

	cacheManager := cache.NewManager(hermesSvc, userSvc, redis)

	domainSign, domainVerify, serviceKey, appVerify := initKeyProviders(cacheManager)
	tokenSvc := token.NewService(cacheManager, domainSign, domainVerify, serviceKey, appVerify)
	logger.Info("[Auth] Token Service 初始化完成")

	emailSender := initMailSender()
	if emailSender != nil {
		logger.Info("[Auth] 邮件发送器初始化完成")
	}

	webauthnSvc, captchaVerifier, totpVerifier := initProviders(credentialSvc, cacheManager, userSvc)

	throttler := throttle.NewThrottler(redis)
	ac := accessctl.NewManager(throttler)
	logger.Info("[Auth] 访问控制管理器初始化完成")

	registry := initRegistry(userSvc, cacheManager, emailSender, webauthnSvc, captchaVerifier, totpVerifier, ac, tokenSvc)

	pool, err := async.NewPool(64)
	if err != nil {
		return nil, err
	}

	userService := user.NewService(cacheManager, userSvc)
	authenticateSvc := authenticate.NewService(cacheManager, ac)
	authorizeSvc := authorize.NewService(cacheManager, hermesSvc, userService, tokenSvc, pool, 5*time.Minute)
	challengeSvc := challenge.NewService(cacheManager, registry)
	mfaSvc := NewMFAService(webauthnSvc)

	handler := NewHandler(authenticateSvc, authorizeSvc, challengeSvc, userService, cacheManager, tokenSvc, mfaSvc, pool)
	logger.Info("[Auth] 模块初始化完成")
	return handler, nil
}

type keySelector func(cache.Key) []byte

func selectPrivateKey(k cache.Key) []byte { return k.PrivateKey }
func selectPublicKey(k cache.Key) []byte  { return k.PublicKey }
func selectSecretKey(k cache.Key) []byte  { return k.SecretKey }

func extractKeys(keys []cache.Key, sel keySelector) [][]byte {
	result := make([][]byte, len(keys))
	for i, k := range keys {
		result[i] = sel(k)
	}
	return result
}

func domainKeyProvider(cm *cache.Manager, ssoID string, sel keySelector) key.MultiOf {
	return func(ctx context.Context, clientID string) ([][]byte, error) {
		if clientID == ssoID {
			k, err := cm.GetSSOKeys()
			if err != nil {
				return nil, err
			}
			return extractKeys(k.Keys, sel), nil
		}
		app, err := cm.GetApplication(ctx, clientID)
		if err != nil {
			return nil, fmt.Errorf("get application: %w", err)
		}
		domain, err := cm.GetDomain(ctx, app.DomainID)
		if err != nil {
			return nil, fmt.Errorf("get domain: %w", err)
		}
		return extractKeys(domain.Keys.Keys, sel), nil
	}
}

func initKeyProviders(cm *cache.Manager) (key.MultiOf, key.MultiOf, key.MultiOf, key.MultiOf) {
	domainSign := domainKeyProvider(cm, token.SSOIssuer, selectPrivateKey)
	domainVerify := domainKeyProvider(cm, token.SSOIssuer, selectPublicKey)

	serviceKey := key.MultiOf(func(ctx context.Context, audience string) ([][]byte, error) {
		if audience == token.SSOAudience {
			k, err := cm.GetSSOKeys()
			if err != nil {
				return nil, err
			}
			return extractKeys(k.Keys, selectSecretKey), nil
		}
		svc, err := cm.GetService(ctx, audience)
		if err != nil {
			return nil, fmt.Errorf("get service: %w", err)
		}
		return extractKeys(svc.Keys.Keys, selectSecretKey), nil
	})

	appVerify := key.MultiOf(func(ctx context.Context, clientID string) ([][]byte, error) {
		app, err := cm.GetApplication(ctx, clientID)
		if err != nil {
			return nil, fmt.Errorf("get application: %w", err)
		}
		return extractKeys(app.Keys.Keys, selectPublicKey), nil
	})

	return domainSign, domainVerify, serviceKey, appVerify
}

// initProviders 初始化底层 Provider（WebAuthn、Captcha、TOTP）
func initProviders(credentialSvc *hermes.CredentialService, cacheManager *cache.Manager, userSvc *hermes.UserService) (*webauthn.Service, captcha.Verifier, factor.TOTPVerifier) {
	// WebAuthn
	var webauthnSvc *webauthn.Service
	if svc, err := webauthn.NewService(cacheManager, userSvc); err != nil {
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
		panic("vchan.captcha.turnstile.app_id or vchan.captcha.turnstile.secret is not set")
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
