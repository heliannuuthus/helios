package config

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"time"
)

// Aegis 配置 Key 常量
const (
	// Aegis 基础配置
	DefaultAegisEndpoint         = "https://aegis.heliannuuthus.com"
	DefaultAegisCookieDomain     = "aegis.heliannuuthus.com"
	DefaultAegisCookiePath       = "/"
	DefaultAegisCookieMaxAge     = 600
	DefaultAegisEndpointLogin    = "/login"
	DefaultAegisEndpointConsent  = "/consent"
	DefaultAegisEndpointMFA      = "/mfa"
	DefaultAegisEndpointError    = "/error"
	DefaultAegisEndpointCallback = "/callback"

	// Cache 默认值
	DefaultAegisCacheSize       = int64(1000)
	DefaultAegisCacheNumCounter = int64(10000)
	DefaultAegisCacheBufferItem = int64(64)
	DefaultAegisCacheTTL        = 2 * time.Minute

	// Redis 缓存过期时间默认值
	DefaultAegisAuthFlowExpiresIn     = 10 * time.Minute
	DefaultAegisAuthCodeExpiresIn     = 5 * time.Minute
	DefaultAegisOTPExpiresIn          = 5 * time.Minute
	DefaultAegisChallengeExpiresIn    = 5 * time.Minute
	DefaultAegisRefreshTokenExpiresIn = 7 * 24 * time.Hour
)

// ==================== 基础配置 ====================

// GetAegisEndpoint 获取 Aegis 服务端点
func GetAegisEndpoint() string {
	endpoint := Aegis().GetString(AegisEndpoint)
	if endpoint == "" {
		return DefaultAegisEndpoint
	}
	return endpoint
}

// GetAegisIssuer 获取 Issuer（endpoint + /api）
func GetAegisIssuer() string {
	return GetAegisEndpoint() + "/api"
}

// ==================== Cookie 配置 ====================

// GetAegisCookieDomain 获取 Cookie 域名
func GetAegisCookieDomain() string {
	domain := Aegis().GetString(AegisCookieDomain)
	if domain == "" {
		// 从 Endpoint 提取域名
		endpoint := GetAegisEndpoint()
		if u, err := url.Parse(endpoint); err == nil {
			return u.Hostname()
		}
		return DefaultAegisCookieDomain
	}
	return domain
}

// GetAegisCookiePath 获取 Cookie 路径
func GetAegisCookiePath() string {
	path := Aegis().GetString(AegisCookiePath)
	if path == "" {
		return DefaultAegisCookiePath
	}
	return path
}

// GetAegisCookieSecure 获取 Cookie Secure 标志
func GetAegisCookieSecure() bool {
	return Aegis().GetBool(AegisCookieSecure)
}

// GetAegisCookieHTTPOnly 获取 Cookie HTTPOnly 标志
func GetAegisCookieHTTPOnly() bool {
	return Aegis().GetBool(AegisCookieHTTPOnly)
}

// GetAegisCookieMaxAge 获取 Cookie 最大存活时间
func GetAegisCookieMaxAge() int {
	maxAge := Aegis().GetInt(AegisCookieMaxAge)
	if maxAge == 0 {
		return DefaultAegisCookieMaxAge
	}
	return maxAge
}

// ==================== Endpoint 配置 ====================

// GetAegisEndpointLogin 获取登录端点
func GetAegisEndpointLogin() string {
	endpoint := Aegis().GetString(AegisEndpoint + "/login")
	if endpoint == "" {
		return DefaultAegisEndpointLogin
	}
	return endpoint
}

// GetAegisEndpointConsent 获取授权同意端点
func GetAegisEndpointConsent() string {
	endpoint := Aegis().GetString(AegisEndpoint + "/consent")
	if endpoint == "" {
		return DefaultAegisEndpointConsent
	}
	return endpoint
}

// GetAegisEndpointMFA 获取 MFA 端点
func GetAegisEndpointMFA() string {
	endpoint := Aegis().GetString(AegisEndpoint + "/mfa")
	if endpoint == "" {
		return DefaultAegisEndpointMFA
	}
	return endpoint
}

// GetAegisEndpointError 获取错误端点
func GetAegisEndpointError() string {
	endpoint := Aegis().GetString(AegisEndpoint + "/error")
	if endpoint == "" {
		return DefaultAegisEndpointError
	}
	return endpoint
}

// GetAegisEndpointCallback 获取回调端点
func GetAegisEndpointCallback() string {
	endpoint := Aegis().GetString(AegisEndpoint + "/callback")
	if endpoint == "" {
		return DefaultAegisEndpointCallback
	}
	return endpoint
}

// ==================== Domain 配置 ====================

// GetAegisDomainSignKey 获取域签名密钥（原始字符串）
func GetAegisDomainSignKey(domainID string) string {
	return Aegis().GetString(AegisDomains + "." + domainID + ".sign-key")
}

// GetAegisDomainSignKeyBytes 获取域签名密钥（解码后的 JWK JSON 字节）
// 配置格式: Base64URL 编码的 JWK JSON
func GetAegisDomainSignKeyBytes(domainID string) ([]byte, error) {
	keyStr := GetAegisDomainSignKey(domainID)
	if keyStr == "" {
		return nil, fmt.Errorf("域 %s 签名密钥不存在", domainID)
	}

	// Base64URL 解码
	keyBytes, err := base64.RawURLEncoding.DecodeString(keyStr)
	if err != nil {
		return nil, fmt.Errorf("解码签名密钥失败: %w", err)
	}

	return keyBytes, nil
}

// GetAegisDomainName 获取域名称
func GetAegisDomainName(domainID string) string {
	return Aegis().GetString(AegisDomains + "." + domainID + ".name")
}

// GetAegisDomainDescription 获取域描述
func GetAegisDomainDescription(domainID string) string {
	return Aegis().GetString(AegisDomains + "." + domainID + ".description")
}

// ==================== Cache 配置 ====================

// GetAegisCacheKeyPrefix 获取缓存 key 前缀
func GetAegisCacheKeyPrefix(cacheType string) string {
	if prefix := Aegis().GetString("aegis.cache." + cacheType + ".prefix"); prefix != "" {
		return prefix
	}
	// 默认前缀映射
	defaultPrefixes := map[string]string{
		// Redis 缓存（认证相关）
		"auth_flow":     "auth:flow:",
		"auth_code":     "auth:code:",
		"refresh_token": "auth:rt:",
		"user_token":    "auth:user:rt:",
		"otp":           "auth:otp:",
		"challenge":     "auth:ch:",
		// 本地缓存（实体数据）
		"domain":                       "domain:",
		"application":                  "app:",
		"service":                      "svc:",
		"user":                         "user:",
		"application-service-relation": "app-svc-rel:",
		"app-service":                  "app-svc:",
	}
	if prefix, ok := defaultPrefixes[cacheType]; ok {
		return prefix
	}
	return cacheType + ":"
}

// GetAegisCacheSize 获取缓存大小
func GetAegisCacheSize(cacheType string) int64 {
	if val := Aegis().GetInt64("aegis.cache." + cacheType + ".cache-size"); val > 0 {
		return val
	}
	return DefaultAegisCacheSize
}

// GetAegisCacheNumCounters 获取缓存计数器数量
func GetAegisCacheNumCounters(cacheType string) int64 {
	if val := Aegis().GetInt64("aegis.cache." + cacheType + ".num-counters"); val > 0 {
		return val
	}
	return DefaultAegisCacheNumCounter
}

// GetAegisCacheBufferItems 获取缓存缓冲区大小
func GetAegisCacheBufferItems(cacheType string) int64 {
	if val := Aegis().GetInt64("aegis.cache." + cacheType + ".buffer-items"); val > 0 {
		return val
	}
	return DefaultAegisCacheBufferItem
}

// GetAegisCacheTTL 获取本地缓存 TTL
func GetAegisCacheTTL(cacheType string) time.Duration {
	if ttl := Aegis().GetDuration("aegis.cache." + cacheType + ".ttl"); ttl > 0 {
		return ttl
	}
	return DefaultAegisCacheTTL
}

// GetAegisAuthFlowExpiresIn 获取 AuthFlow 过期时间
func GetAegisAuthFlowExpiresIn() time.Duration {
	if val := Aegis().GetDuration("aegis.cache.auth_flow.expires_in"); val > 0 {
		return val
	}
	return DefaultAegisAuthFlowExpiresIn
}

// GetAegisAuthCodeExpiresIn 获取 AuthCode 过期时间
func GetAegisAuthCodeExpiresIn() time.Duration {
	if val := Aegis().GetDuration("aegis.cache.auth_code.expires_in"); val > 0 {
		return val
	}
	return DefaultAegisAuthCodeExpiresIn
}

// GetAegisOTPExpiresIn 获取 OTP 过期时间
func GetAegisOTPExpiresIn() time.Duration {
	if val := Aegis().GetDuration("aegis.cache.otp.expires_in"); val > 0 {
		return val
	}
	return DefaultAegisOTPExpiresIn
}

// GetAegisChallengeExpiresIn 获取 Challenge 过期时间
func GetAegisChallengeExpiresIn() time.Duration {
	if val := Aegis().GetDuration("aegis.cache.challenge.expires_in"); val > 0 {
		return val
	}
	return DefaultAegisChallengeExpiresIn
}

// GetAegisRefreshTokenExpiresIn 获取 RefreshToken 过期时间
func GetAegisRefreshTokenExpiresIn() time.Duration {
	if val := Aegis().GetDuration("aegis.cache.refresh_token.expires_in"); val > 0 {
		return val
	}
	return DefaultAegisRefreshTokenExpiresIn
}

// ==================== Mail 配置 ====================

// MailConfig 邮件配置
type MailConfig struct {
	Enabled  bool
	Provider string // qq-exmail, qq, 163, gmail, outlook, aliyun, custom
	Host     string
	Port     int
	UseSSL   bool
	Username string
	Password string
}

// IsMailEnabled 检查是否启用邮件服务
func IsMailEnabled() bool {
	return Aegis().GetBool("mail.enabled")
}

// GetMailConfig 获取邮件配置
func GetMailConfig() *MailConfig {
	cfg := Aegis()

	provider := cfg.GetString("mail.provider")
	if provider == "" {
		provider = "qq-exmail"
	}

	// 根据 provider 设置默认的 host 和 port
	host := cfg.GetString("mail.host")
	port := cfg.GetInt("mail.port")
	useSSL := cfg.GetBool("mail.use-ssl")

	if host == "" {
		switch provider {
		case "qq-exmail":
			host = "smtp.exmail.qq.com"
			if port == 0 {
				port = 465
			}
			useSSL = true
		case "qq":
			host = "smtp.qq.com"
			if port == 0 {
				port = 465
			}
			useSSL = true
		case "163":
			host = "smtp.163.com"
			if port == 0 {
				port = 465
			}
			useSSL = true
		case "gmail":
			host = "smtp.gmail.com"
			if port == 0 {
				port = 587
			}
			useSSL = false
		case "outlook":
			host = "smtp.office365.com"
			if port == 0 {
				port = 587
			}
			useSSL = false
		case "aliyun":
			host = "smtp.mxhichina.com"
			if port == 0 {
				port = 465
			}
			useSSL = true
		}
	}

	if port == 0 {
		port = 587
	}

	return &MailConfig{
		Enabled:  cfg.GetBool("mail.enabled"),
		Provider: provider,
		Host:     host,
		Port:     port,
		UseSSL:   useSSL,
		Username: cfg.GetString("mail.username"),
		Password: cfg.GetString("mail.password"),
	}
}

// ==================== Secret 配置 ====================

// GetAegisSecret 获取 audience 对应的 secret（base64url 编码的 JWK JSON）
func GetAegisSecret(audience string) string {
	return Aegis().GetString(AegisSecrets + "." + audience)
}

// GetAegisSecretBytes 获取 audience 对应的 secret（解码后的 JWK JSON 字节）
func GetAegisSecretBytes(audience string) ([]byte, error) {
	secretStr := GetAegisSecret(audience)
	if secretStr == "" {
		return nil, fmt.Errorf("audience %s 的 secret 不存在", audience)
	}

	// base64url 解码
	secretBytes, err := base64.RawURLEncoding.DecodeString(secretStr)
	if err != nil {
		return nil, fmt.Errorf("解码 audience %s 的 secret 失败: %w", audience, err)
	}

	return secretBytes, nil
}
