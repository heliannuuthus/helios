package main

import (
	"context"
	"fmt"
	"time"

	"github.com/heliannuuthus/aegis/auth"
	"github.com/heliannuuthus/aegis/config"
	"github.com/heliannuuthus/aegis/internal/authenticate"
	"github.com/heliannuuthus/aegis/internal/authenticator"
	"github.com/heliannuuthus/aegis/internal/authenticator/captcha"
	"github.com/heliannuuthus/aegis/internal/authenticator/factor"
	"github.com/heliannuuthus/aegis/internal/authenticator/idp"
	"github.com/heliannuuthus/aegis/internal/authenticator/idp/alipay"
	"github.com/heliannuuthus/aegis/internal/authenticator/idp/github"
	"github.com/heliannuuthus/aegis/internal/authenticator/idp/google"
	"github.com/heliannuuthus/aegis/internal/authenticator/idp/passkey"
	"github.com/heliannuuthus/aegis/internal/authenticator/idp/staff"
	"github.com/heliannuuthus/aegis/internal/authenticator/idp/tt"
	idpuser "github.com/heliannuuthus/aegis/internal/authenticator/idp/user"
	"github.com/heliannuuthus/aegis/internal/authenticator/idp/wechat"
	"github.com/heliannuuthus/aegis/internal/authenticator/vchan"
	"github.com/heliannuuthus/aegis/internal/authenticator/webauthn"
	"github.com/heliannuuthus/aegis/internal/authorize"
	"github.com/heliannuuthus/aegis/internal/cache"
	"github.com/heliannuuthus/aegis/internal/challenge"
	internalmfa "github.com/heliannuuthus/aegis/internal/mfa"
	"github.com/heliannuuthus/aegis/internal/token"
	"github.com/heliannuuthus/aegis/internal/user"
	"github.com/heliannuuthus/aegis/profile"
	"github.com/heliannuuthus/aegis/rpc/hermes"
	"github.com/heliannuuthus/pkg/accessctl"
	"github.com/heliannuuthus/pkg/aegis/utilities/key"
	"github.com/heliannuuthus/pkg/async"
	"github.com/heliannuuthus/pkg/logger"
	"github.com/heliannuuthus/pkg/mail"
	"github.com/heliannuuthus/pkg/throttle"
)

func initializeAegis(hermesClient *hermes.Client, cacheManager *cache.Manager) (*auth.Handler, error) {
	if hermesClient == nil {
		return nil, fmt.Errorf("hermes client is required")
	}
	if cacheManager == nil {
		return nil, fmt.Errorf("cache manager is required")
	}
	if err := warmupRequiredKeys(cacheManager); err != nil {
		return nil, fmt.Errorf("加载必需密钥失败: %w", err)
	}

	domainSign, domainVerify, serviceKey, appVerify := initKeyProviders(cacheManager)
	tokenSvc := token.NewService(cacheManager, domainSign, domainVerify, serviceKey, appVerify)
	logger.Info("[Auth] Token Service 初始化完成")

	emailSender, err := initMailSender()
	if err != nil {
		return nil, err
	}
	logger.Info("[Auth] 邮件发送器初始化完成")

	webauthnSvc, captchaVerifier, err := initProviders(cacheManager, hermesClient)
	if err != nil {
		return nil, err
	}

	throttler := throttle.NewThrottler(cacheManager.Redis())
	ac := accessctl.NewManager(throttler)
	logger.Info("[Auth] 访问控制管理器初始化完成")

	mfaSvc := internalmfa.NewService(hermesClient, cacheManager, webauthnSvc)

	registry := initRegistry(hermesClient, cacheManager, emailSender, mfaSvc.TOTP(), webauthnSvc, captchaVerifier, ac, tokenSvc)

	pool, err := async.NewPool(64)
	if err != nil {
		return nil, err
	}

	userService := user.NewService(cacheManager, hermesClient)
	authenticateSvc := authenticate.NewService(cacheManager, ac)
	authorizeSvc := authorize.NewService(cacheManager, hermesClient, userService, tokenSvc, pool, 5*time.Minute)
	challengeSvc := challenge.NewService(cacheManager, registry)
	profileHandler := profile.NewHandler(hermesClient, mfaSvc)

	handler := auth.NewHandler(authenticateSvc, authorizeSvc, challengeSvc, userService, cacheManager, tokenSvc, profileHandler, pool)
	logger.Info("[Auth] 模块初始化完成")
	return handler, nil
}

func warmupRequiredKeys(cacheManager *cache.Manager) error {
	if _, err := cacheManager.GetSSOKeys(); err != nil {
		return fmt.Errorf("加载 SSO 密钥: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := cacheManager.GetService(ctx, config.GetIrisAudience()); err != nil {
		return fmt.Errorf("加载 Iris 服务密钥: %w", err)
	}
	return nil
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

// initProviders 初始化底层认证能力（WebAuthn、Captcha）
func initProviders(cacheManager *cache.Manager, hermesClient *hermes.Client) (*webauthn.Service, captcha.Verifier, error) {
	webauthnSvc, err := webauthn.NewService(cacheManager, hermesClient)
	if err != nil {
		return nil, nil, fmt.Errorf("init webauthn service: %w", err)
	}
	logger.Info("[Auth] WebAuthn 初始化完成")

	// Captcha
	captchaVerifier, err := initCaptchaVerifier()
	if err != nil {
		return nil, nil, fmt.Errorf("init captcha verifier: %w", err)
	}
	logger.Infof("[Auth] Captcha 验证器初始化完成: provider=%s", captchaVerifier.GetProvider())

	return webauthnSvc, captchaVerifier, nil
}

// initRegistry 初始化全局 Registry（注册胶水层 Authenticator）
func initRegistry(hermesClient *hermes.Client, cacheManager *cache.Manager, emailSender *mail.Sender, totpVerifier factor.TOTPVerifier, webauthnSvc *webauthn.Service, captchaVerifier captcha.Verifier, ac *accessctl.Manager, tokenVerifier authenticate.ChallengeTokenVerifier) *authenticator.Registry {
	registry := authenticator.NewRegistry()

	// ==================== IDP Authenticators ====================

	registerIDP := func(p idp.Provider) {
		registry.Register(authenticate.NewIDPAuthenticator(p))
	}

	registerIDP(wechat.NewMPProvider(cacheManager))
	registerIDP(tt.NewMPProvider(cacheManager))
	registerIDP(alipay.NewMPProvider(cacheManager))
	registerIDP(github.NewProvider(cacheManager))
	registerIDP(google.NewProvider(cacheManager))

	registerIDP(idpuser.NewProvider(hermesClient))
	registerIDP(staff.NewProvider(hermesClient))

	registerIDP(passkey.NewProvider(webauthnSvc))
	logger.Info("[Auth] Passkey IDP 注册完成")

	// ==================== VChan Authenticators ====================

	registry.Register(authenticate.NewVChanAuthenticator(vchan.NewCaptchaProvider(captchaVerifier)))

	// ==================== Factor Authenticators ====================

	registry.Register(authenticate.NewFactorAuthenticator(factor.NewEmailOTPProvider(emailSender, cacheManager), ac, tokenVerifier))

	registry.Register(authenticate.NewFactorAuthenticator(factor.NewTOTPFactor(totpVerifier), ac, tokenVerifier))

	registry.Register(authenticate.NewFactorAuthenticator(factor.NewWebAuthnProvider(webauthnSvc, hermesClient), ac, tokenVerifier))

	logger.Infof("[Auth] Registry 初始化完成: %v", registry.Summary())
	return registry
}

// initCaptchaVerifier 初始化 Captcha 验证器
func initCaptchaVerifier() (captcha.Verifier, error) {
	cfg := config.Cfg()

	siteKey := cfg.GetString("vchan.captcha.turnstile.app_id")
	secretKey := cfg.GetString("vchan.captcha.turnstile.secret")
	if siteKey == "" || secretKey == "" {
		return nil, fmt.Errorf("vchan.captcha.turnstile.app_id or vchan.captcha.turnstile.secret is not set")
	}
	return captcha.NewTurnstileVerifier(siteKey, secretKey), nil
}

// initMailSender 初始化邮件发送器
func initMailSender() (*mail.Sender, error) {
	cfg := config.GetMailConfig()

	sender, err := mail.NewSender(&mail.SenderConfig{
		Host:     cfg.Host,
		Port:     cfg.Port,
		Username: cfg.Username,
		Password: cfg.Password,
		UseSSL:   cfg.UseSSL,
	})
	if err != nil {
		return nil, fmt.Errorf("创建邮件发送器失败: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := sender.Verify(ctx); err != nil {
		sender.Close()
		return nil, fmt.Errorf("验证邮件发送器失败: %w", err)
	}

	logger.Infof("[Auth] 邮件连接池初始化成功: %s:%d", cfg.Host, cfg.Port)
	return sender, nil
}
