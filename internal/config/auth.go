package config

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
)

// Auth 配置 Key 常量
const (
	// App 配置
	AuthAppDebug   = "app.debug"
	AuthAppName    = "app.name"
	AuthAppVersion = "app.version"
	AuthAppEnv     = "app.env"

	// Server 配置
	AuthServerHost = "server.host"
	AuthServerPort = "server.port"

	// Log 配置
	AuthLogLevel  = "log.level"
	AuthLogFormat = "log.format"

	// CORS 配置
	AuthCORSOrigins          = "cors.origins"
	AuthCORSAllowCredentials = "cors.allow_credentials"
	AuthCORSAllowMethods     = "cors.allow_methods"
	AuthCORSAllowHeaders     = "cors.allow_headers"

	// Auth 基础配置
	AuthIssuer           = "auth.issuer"
	AuthAudience         = "auth.audience"
	AuthExpiresIn        = "auth.expires-in"
	AuthRefreshExpiresIn = "auth.refresh-expires-in"
	AuthMaxRefreshToken  = "auth.max-refresh-token"

	// Auth Cookie 配置
	AuthCookieDomain   = "auth.cookie.domain"
	AuthCookiePath     = "auth.cookie.path"
	AuthCookieSecure   = "auth.cookie.secure"
	AuthCookieHTTPOnly = "auth.cookie.http-only"
	AuthCookieMaxAge   = "auth.cookie.max-age"

	// Auth Endpoints 配置
	AuthEndpointLogin    = "auth.endpoints.login"
	AuthEndpointConsent  = "auth.endpoints.consent"
	AuthEndpointMFA      = "auth.endpoints.mfa"
	AuthEndpointError    = "auth.endpoints.error"
	AuthEndpointCallback = "auth.endpoints.callback"

	// Auth Domains 配置前缀
	AuthDomains = "auth.domains"

	// KMS 配置
	AuthKMSDatabaseEncKey = "kms.database.enc-key"
	AuthKMSTokenSignKey   = "kms.token.sign-key"
	AuthKMSTokenEncKey    = "kms.token.enc-key"

	// IDP 配置前缀
	AuthIDPWxMP     = "idps.wxmp"
	AuthIDPTT       = "idps.tt"
	AuthIDPAlipay   = "idps.alipay"
	AuthIDPTelegram = "idps.telegram"

	// Cache 配置前缀
	AuthCacheDomain                     = "auth.cache.domain"
	AuthCacheApplication                = "auth.cache.application"
	AuthCacheService                    = "auth.cache.service"
	AuthCacheUser                       = "auth.cache.user"
	AuthCacheApplicationServiceRelation = "auth.cache.application-service-relation"
	AuthCacheRelationship               = "auth.cache.relationship"
)

// Auth 配置默认值
const (
	DefaultAuthIssuer           = "https://auth.heliannuuthus.com/api"
	DefaultAuthCookieDomain     = "auth.heliannuuthus.com"
	DefaultAuthCookiePath       = "/"
	DefaultAuthCookieMaxAge     = 600
	DefaultAuthEndpointLogin    = "/login"
	DefaultAuthEndpointConsent  = "/consent"
	DefaultAuthEndpointMFA      = "/mfa"
	DefaultAuthEndpointError    = "/error"
	DefaultAuthEndpointCallback = "/callback"
	DefaultAuthExpiresIn        = 3600
	DefaultAuthRefreshExpiresIn = 604800
	DefaultAuthMaxRefreshToken  = 5
)

// GetAuthIssuer 获取 Issuer
func GetAuthIssuer() string {
	issuer := Auth().GetString(AuthIssuer)
	if issuer == "" {
		return DefaultAuthIssuer
	}
	return issuer
}

// GetAuthCookieDomain 获取 Cookie 域名
func GetAuthCookieDomain() string {
	domain := Auth().GetString(AuthCookieDomain)
	if domain == "" {
		// 从 Issuer 提取域名
		issuer := GetAuthIssuer()
		if u, err := url.Parse(issuer); err == nil {
			return u.Hostname()
		}
		return DefaultAuthCookieDomain
	}
	return domain
}

// GetAuthCookiePath 获取 Cookie 路径
func GetAuthCookiePath() string {
	path := Auth().GetString(AuthCookiePath)
	if path == "" {
		return DefaultAuthCookiePath
	}
	return path
}

// GetAuthCookieSecure 获取 Cookie Secure 标志
func GetAuthCookieSecure() bool {
	return Auth().GetBool(AuthCookieSecure)
}

// GetAuthCookieHTTPOnly 获取 Cookie HTTPOnly 标志
func GetAuthCookieHTTPOnly() bool {
	return Auth().GetBool(AuthCookieHTTPOnly)
}

// GetAuthCookieMaxAge 获取 Cookie 最大存活时间
func GetAuthCookieMaxAge() int {
	maxAge := Auth().GetInt(AuthCookieMaxAge)
	if maxAge == 0 {
		return DefaultAuthCookieMaxAge
	}
	return maxAge
}

// GetAuthEndpointLogin 获取登录端点
func GetAuthEndpointLogin() string {
	endpoint := Auth().GetString(AuthEndpointLogin)
	if endpoint == "" {
		return DefaultAuthEndpointLogin
	}
	return endpoint
}

// GetAuthEndpointConsent 获取授权同意端点
func GetAuthEndpointConsent() string {
	endpoint := Auth().GetString(AuthEndpointConsent)
	if endpoint == "" {
		return DefaultAuthEndpointConsent
	}
	return endpoint
}

// GetAuthEndpointMFA 获取 MFA 端点
func GetAuthEndpointMFA() string {
	endpoint := Auth().GetString(AuthEndpointMFA)
	if endpoint == "" {
		return DefaultAuthEndpointMFA
	}
	return endpoint
}

// GetAuthEndpointError 获取错误端点
func GetAuthEndpointError() string {
	endpoint := Auth().GetString(AuthEndpointError)
	if endpoint == "" {
		return DefaultAuthEndpointError
	}
	return endpoint
}

// GetAuthEndpointCallback 获取回调端点
func GetAuthEndpointCallback() string {
	endpoint := Auth().GetString(AuthEndpointCallback)
	if endpoint == "" {
		return DefaultAuthEndpointCallback
	}
	return endpoint
}

// GetAuthDomainSignKey 获取域签名密钥（原始字符串）
func GetAuthDomainSignKey(domainID string) string {
	return Auth().GetString(AuthDomains + "." + domainID + ".sign-key")
}

// GetAuthDomainEncryptKey 获取域加密密钥（原始字符串）
func GetAuthDomainEncryptKey(domainID string) string {
	return Auth().GetString(AuthDomains + "." + domainID + ".encrypt-key")
}

// GetAuthDomainSignKeyBytes 获取域签名密钥（解码后的字节）
func GetAuthDomainSignKeyBytes(domainID string) ([]byte, error) {
	keyStr := GetAuthDomainSignKey(domainID)
	if keyStr == "" {
		return nil, fmt.Errorf("域 %s 签名密钥不存在", domainID)
	}

	// 解析密钥格式：算法:base64密钥
	parts := strings.SplitN(keyStr, ":", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("无效的签名密钥格式")
	}

	keyBytes, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("解码签名密钥失败: %w", err)
	}

	return keyBytes, nil
}

// GetAuthDomainEncryptKeyBytes 获取域加密密钥（解码后的字节）
func GetAuthDomainEncryptKeyBytes(domainID string) ([]byte, error) {
	keyStr := GetAuthDomainEncryptKey(domainID)
	if keyStr == "" {
		return nil, fmt.Errorf("域 %s 加密密钥不存在", domainID)
	}

	// 解析密钥格式：算法:base64密钥
	parts := strings.SplitN(keyStr, ":", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("无效的加密密钥格式")
	}

	keyBytes, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("解码加密密钥失败: %w", err)
	}

	return keyBytes, nil
}

// GetAuthDomainName 获取域名称
func GetAuthDomainName(domainID string) string {
	return Auth().GetString(AuthDomains + "." + domainID + ".name")
}

// GetAuthDomainDescription 获取域描述
func GetAuthDomainDescription(domainID string) string {
	return Auth().GetString(AuthDomains + "." + domainID + ".description")
}

// IDP 配置获取函数

// GetIDPWxMPAppID 获取微信小程序 AppID
func GetIDPWxMPAppID() string {
	return Auth().GetString(AuthIDPWxMP + ".appid")
}

// GetIDPWxMPSecret 获取微信小程序 Secret
func GetIDPWxMPSecret() string {
	return Auth().GetString(AuthIDPWxMP + ".secret")
}

// GetIDPTTAppID 获取抖音小程序 AppID
func GetIDPTTAppID() string {
	return Auth().GetString(AuthIDPTT + ".appid")
}

// GetIDPTTSecret 获取抖音小程序 Secret
func GetIDPTTSecret() string {
	return Auth().GetString(AuthIDPTT + ".secret")
}

// GetIDPAlipayAppID 获取支付宝小程序 AppID
func GetIDPAlipayAppID() string {
	return Auth().GetString(AuthIDPAlipay + ".appid")
}

// GetIDPAlipaySecret 获取支付宝应用私钥
func GetIDPAlipaySecret() string {
	return Auth().GetString(AuthIDPAlipay + ".secret")
}

// GetIDPAlipayVerifyKey 获取支付宝公钥
func GetIDPAlipayVerifyKey() string {
	return Auth().GetString(AuthIDPAlipay + ".verify-key")
}

// GetIDPAlipayEncKey 获取支付宝加密密钥
func GetIDPAlipayEncKey() string {
	return Auth().GetString(AuthIDPAlipay + ".enc-key")
}

// GetIDPTelegramBotToken 获取 Telegram Bot Token
func GetIDPTelegramBotToken() string {
	return Auth().GetString(AuthIDPTelegram + ".bot-token")
}

// GetIDPTelegramBotUsername 获取 Telegram Bot 用户名
func GetIDPTelegramBotUsername() string {
	return Auth().GetString(AuthIDPTelegram + ".bot-username")
}

// GetIDPTelegramDomain 获取 Telegram 域名
func GetIDPTelegramDomain() string {
	return Auth().GetString(AuthIDPTelegram + ".domain")
}

// Cache 配置获取函数

// GetAuthCacheKeyPrefix 获取缓存 key 前缀
func GetAuthCacheKeyPrefix(cacheType string) string {
	return Auth().GetString("auth.cache." + cacheType + ".key-prefix")
}

// GetAuthCacheSize 获取缓存大小
func GetAuthCacheSize(cacheType string) int64 {
	return Auth().GetInt64("auth.cache." + cacheType + ".cache-size")
}

// GetAuthCacheNumCounters 获取缓存计数器数量
func GetAuthCacheNumCounters(cacheType string) int64 {
	return Auth().GetInt64("auth.cache." + cacheType + ".num-counters")
}

// GetAuthCacheBufferItems 获取缓存缓冲区大小
func GetAuthCacheBufferItems(cacheType string) int64 {
	return Auth().GetInt64("auth.cache." + cacheType + ".buffer-items")
}

// GetAuthCacheTTL 获取缓存 TTL
func GetAuthCacheTTL(cacheType string) string {
	return Auth().GetString("auth.cache." + cacheType + ".ttl")
}
