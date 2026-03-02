package config

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"time"

	baseconfig "github.com/heliannuuthus/helios/pkg/config"
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
	DefaultAegisEndpointCallback = "/callback"

	// Cache 默认值
	DefaultAegisCacheSize       = int64(1000)
	DefaultAegisCacheNumCounter = int64(10000)
	DefaultAegisCacheBufferItem = int64(64)
	DefaultAegisCacheTTL        = 2 * time.Minute

	// Redis 缓存过期时间默认值
	DefaultAegisAuthFlowExpiresIn     = 10 * time.Minute
	DefaultAegisAuthFlowMaxLifetime   = 1 * time.Hour
	DefaultAegisAuthCodeExpiresIn     = 5 * time.Minute
	DefaultAegisOTPExpiresIn          = 5 * time.Minute
	DefaultAegisChallengeExpiresIn    = 5 * time.Minute
	DefaultAegisRefreshTokenExpiresIn = 7 * 24 * time.Hour
	DefaultAegisPublicKeyCacheMaxAge  = 3 * time.Hour
)

// Cfg 返回 Aegis 配置单例
func Cfg() *baseconfig.Cfg {
	return baseconfig.Aegis()
}

// ==================== 基础配置 ====================

// GetEndpoint 获取 Aegis 服务端点
func GetEndpoint() string {
	endpoint := Cfg().GetString("aegis.endpoint")
	if endpoint == "" {
		return DefaultAegisEndpoint
	}
	return endpoint
}

// GetIssuer 获取 Issuer（endpoint + /api）
func GetIssuer() string {
	return GetEndpoint() + "/api"
}

// ==================== Cookie 配置 ====================

// GetCookieDomain 获取 Cookie 域名
func GetCookieDomain() string {
	domain := Cfg().GetString("aegis.cookie.domain")
	if domain == "" {
		endpoint := GetEndpoint()
		if u, err := url.Parse(endpoint); err == nil {
			return u.Hostname()
		}
		return DefaultAegisCookieDomain
	}
	return domain
}

// GetCookiePath 获取 Cookie 路径
func GetCookiePath() string {
	path := Cfg().GetString("aegis.cookie.path")
	if path == "" {
		return DefaultAegisCookiePath
	}
	return path
}

// GetCookieSecure 获取 Cookie Secure 标志（默认 true，SameSite=None 要求 Secure）
func GetCookieSecure() bool {
	if Cfg().IsSet("aegis.cookie.secure") {
		return Cfg().GetBool("aegis.cookie.secure")
	}
	return true
}

// GetCookieHTTPOnly 获取 Cookie HTTPOnly 标志（默认 true，防止 XSS 读取 session cookie）
func GetCookieHTTPOnly() bool {
	if Cfg().IsSet("aegis.cookie.http-only") {
		return Cfg().GetBool("aegis.cookie.http-only")
	}
	return true
}

// GetCookieMaxAge 获取 Cookie 最大存活时间
func GetCookieMaxAge() int {
	maxAge := Cfg().GetInt("aegis.cookie.max-age")
	if maxAge == 0 {
		return DefaultAegisCookieMaxAge
	}
	return maxAge
}

// ==================== Endpoint 配置 ====================

// GetEndpointLogin 获取登录端点
func GetEndpointLogin() string {
	endpoint := Cfg().GetString("aegis.endpoint/login")
	if endpoint == "" {
		return DefaultAegisEndpointLogin
	}
	return endpoint
}

// GetEndpointConsent 获取授权同意端点
func GetEndpointConsent() string {
	endpoint := Cfg().GetString("aegis.endpoint/consent")
	if endpoint == "" {
		return DefaultAegisEndpointConsent
	}
	return endpoint
}

// GetEndpointMFA 获取 MFA 端点
func GetEndpointMFA() string {
	endpoint := Cfg().GetString("aegis.endpoint/mfa")
	if endpoint == "" {
		return DefaultAegisEndpointMFA
	}
	return endpoint
}

// GetEndpointCallback 获取回调端点
func GetEndpointCallback() string {
	endpoint := Cfg().GetString("aegis.endpoint/callback")
	if endpoint == "" {
		return DefaultAegisEndpointCallback
	}
	return endpoint
}

// ==================== Cache 配置 ====================

// GetCacheKeyPrefix 获取缓存 key 前缀
func GetCacheKeyPrefix(cacheType string) string {
	if prefix := Cfg().GetString("aegis.cache." + cacheType + ".prefix"); prefix != "" {
		return prefix
	}
	defaultPrefixes := map[string]string{
		"auth_flow":                    "auth:flow:",
		"auth_code":                    "auth:code:",
		"refresh_token":                "auth:rt:",
		"user_token":                   "auth:user:rt:",
		"otp":                          "auth:otp:",
		"challenge":                    "auth:ch:",
		"domain":                       "domain:",
		"application":                  "app:",
		"service":                      "svc:",
		"user":                         "user:",
		"application-service-relation": "app-svc-rel:",
		"app-service":                  "app-svc:",
		"challenge-config":             "ch-cfg:",
	}
	if prefix, ok := defaultPrefixes[cacheType]; ok {
		return prefix
	}
	return cacheType + ":"
}

// GetCacheSize 获取缓存大小
func GetCacheSize(cacheType string) int64 {
	if val := Cfg().GetInt64("aegis.cache." + cacheType + ".cache-size"); val > 0 {
		return val
	}
	return DefaultAegisCacheSize
}

// GetCacheNumCounters 获取缓存计数器数量
func GetCacheNumCounters(cacheType string) int64 {
	if val := Cfg().GetInt64("aegis.cache." + cacheType + ".num-counters"); val > 0 {
		return val
	}
	return DefaultAegisCacheNumCounter
}

// GetCacheBufferItems 获取缓存缓冲区大小
func GetCacheBufferItems(cacheType string) int64 {
	if val := Cfg().GetInt64("aegis.cache." + cacheType + ".buffer-items"); val > 0 {
		return val
	}
	return DefaultAegisCacheBufferItem
}

// GetCacheTTL 获取本地缓存 TTL
func GetCacheTTL(cacheType string) time.Duration {
	if ttl := Cfg().GetDuration("aegis.cache." + cacheType + ".ttl"); ttl > 0 {
		return ttl
	}
	return DefaultAegisCacheTTL
}

// GetAuthFlowExpiresIn 获取 AuthFlow 过期时间
func GetAuthFlowExpiresIn() time.Duration {
	if val := Cfg().GetDuration("aegis.cache.auth_flow.expires_in"); val > 0 {
		return val
	}
	return DefaultAegisAuthFlowExpiresIn
}

// GetAuthFlowMaxLifetime 获取 AuthFlow 最大生命周期
func GetAuthFlowMaxLifetime() time.Duration {
	if val := Cfg().GetDuration("aegis.cache.auth_flow.max_lifetime"); val > 0 {
		return val
	}
	return DefaultAegisAuthFlowMaxLifetime
}

// GetAuthCodeExpiresIn 获取 AuthCode 过期时间
func GetAuthCodeExpiresIn() time.Duration {
	if val := Cfg().GetDuration("aegis.cache.auth_code.expires_in"); val > 0 {
		return val
	}
	return DefaultAegisAuthCodeExpiresIn
}

// GetOTPExpiresIn 获取 OTP 过期时间
func GetOTPExpiresIn() time.Duration {
	if val := Cfg().GetDuration("aegis.cache.otp.expires_in"); val > 0 {
		return val
	}
	return DefaultAegisOTPExpiresIn
}

// GetChallengeExpiresIn 获取 Challenge 缓存过期时间
func GetChallengeExpiresIn() time.Duration {
	if val := Cfg().GetDuration("aegis.cache.challenge.expires_in"); val > 0 {
		return val
	}
	return DefaultAegisChallengeExpiresIn
}

// GetRefreshTokenExpiresIn 获取 RefreshToken 过期时间
func GetRefreshTokenExpiresIn() time.Duration {
	if val := Cfg().GetDuration("aegis.cache.refresh_token.expires_in"); val > 0 {
		return val
	}
	return DefaultAegisRefreshTokenExpiresIn
}

// GetPublicKeyCacheMaxAge 获取公钥缓存最大时间
func GetPublicKeyCacheMaxAge() time.Duration {
	if val := Cfg().GetDuration("aegis.cache.public_key.max_age"); val > 0 {
		return val
	}
	return DefaultAegisPublicKeyCacheMaxAge
}

// ==================== Mail 配置 ====================

// MailConfig 邮件配置
type MailConfig struct {
	Provider string
	Host     string
	Port     int
	UseSSL   bool
	Username string
	Password string
}

// mailProviderDefaults 邮件服务商默认配置
type mailProviderDefaults struct {
	host   string
	port   int
	useSSL bool
}

// getMailProviderDefaults 根据服务商获取默认配置
func getMailProviderDefaults(provider string) mailProviderDefaults {
	defaults := map[string]mailProviderDefaults{
		"qq-exmail": {host: "smtp.exmail.qq.com", port: 465, useSSL: true},
		"qq":        {host: "smtp.qq.com", port: 465, useSSL: true},
		"163":       {host: "smtp.163.com", port: 465, useSSL: true},
		"gmail":     {host: "smtp.gmail.com", port: 587, useSSL: false},
		"outlook":   {host: "smtp.office365.com", port: 587, useSSL: false},
		"aliyun":    {host: "smtp.mxhichina.com", port: 465, useSSL: true},
	}
	if d, ok := defaults[provider]; ok {
		return d
	}
	return mailProviderDefaults{port: 587}
}

// GetMailConfig 获取邮件配置
func GetMailConfig() *MailConfig {
	c := Cfg()
	provider := c.GetString("mail.provider")
	if provider == "" {
		provider = "qq-exmail"
	}
	host := c.GetString("mail.host")
	port := c.GetInt("mail.port")
	useSSL := c.GetBool("mail.use-ssl")
	if host == "" {
		defaults := getMailProviderDefaults(provider)
		host = defaults.host
		if port == 0 {
			port = defaults.port
		}
		useSSL = defaults.useSSL
	}
	if port == 0 {
		port = 587
	}
	return &MailConfig{
		Provider: provider,
		Host:     host,
		Port:     port,
		UseSSL:   useSSL,
		Username: c.GetString("mail.username"),
		Password: c.GetString("mail.password"),
	}
}

// ==================== Challenge 配置 ====================

// DefaultChallengeBusinessExpiresIn Challenge 业务有效期默认值
const DefaultChallengeBusinessExpiresIn = 5 * time.Minute

// GetChallengeBusinessExpiresIn 获取 Challenge 业务有效期
func GetChallengeBusinessExpiresIn() time.Duration {
	if val := Cfg().GetDuration("aegis.challenge.expires-in"); val > 0 {
		return val
	}
	return DefaultChallengeBusinessExpiresIn
}

// ==================== Challenge 限流配置 ====================

// GetRateLimitDefaultLimits 获取 channel 维度的默认限流配置
func GetRateLimitDefaultLimits() map[string]int {
	raw := Cfg().GetStringMap("aegis.challenge.rate-limit.default-limits")
	if len(raw) == 0 {
		return map[string]int{"1m": 1, "1h": 10, "24h": 20}
	}
	return parseIntMap(raw)
}

// GetRateLimitIPLimits 获取 IP 维度的默认限流配置
func GetRateLimitIPLimits() map[string]int {
	raw := Cfg().GetStringMap("aegis.challenge.rate-limit.ip-limits")
	if len(raw) == 0 {
		return map[string]int{"1m": 5, "1h": 50}
	}
	return parseIntMap(raw)
}

// GetRetryAfterFromLimits 从限流配置中提取最小窗口时间作为 retry_after
// 比如 {"1m": 1, "1h": 10} 返回 60 秒
func GetRetryAfterFromLimits(limits map[string]int) int {
	minSeconds := 0
	for window := range limits {
		dur, err := time.ParseDuration(window)
		if err != nil {
			continue
		}
		seconds := int(dur.Seconds())
		if minSeconds == 0 || seconds < minSeconds {
			minSeconds = seconds
		}
	}
	if minSeconds == 0 {
		return 60 // 默认 60 秒
	}
	return minSeconds
}

// ==================== Access Control 配置 ====================

// AC 默认值
const (
	DefaultACCaptchaThreshold = 5 // 全局默认：验证 5 次要求 captcha
	DefaultACFailWindow       = 30 * time.Minute
)

// GetACCaptchaThreshold 获取指定 channelType 的 captcha 阈值
// 优先读 aegis.challenge.access-control.{channelType}.captcha-threshold
// 回退到 aegis.challenge.access-control.captcha-threshold
// 再回退到默认值 5（0 = 始终需要 captcha）
func GetACCaptchaThreshold(channelType string) int {
	cfg := Cfg()
	perType := cfg.GetInt("aegis.challenge.access-control." + channelType + ".captcha-threshold")
	if perType > 0 || cfg.IsSet("aegis.challenge.access-control."+channelType+".captcha-threshold") {
		return perType
	}
	global := cfg.GetInt("aegis.challenge.access-control.captcha-threshold")
	if global > 0 || cfg.IsSet("aegis.challenge.access-control.captcha-threshold") {
		return global
	}
	return DefaultACCaptchaThreshold
}

// GetACFailWindow 获取指定 channelType 的失败统计窗口
func GetACFailWindow(channelType string) time.Duration {
	cfg := Cfg()
	if v := cfg.GetDuration("aegis.challenge.access-control." + channelType + ".fail-window"); v > 0 {
		return v
	}
	if v := cfg.GetDuration("aegis.challenge.access-control.fail-window"); v > 0 {
		return v
	}
	return DefaultACFailWindow
}

// ==================== Login Access Control 配置 ====================

// Login AC 默认值
const (
	DefaultLoginACCaptchaThreshold = 5                // 登录默认：验证 5 次要求 captcha
	DefaultLoginACFailWindow       = 30 * time.Minute // 登录默认：30 分钟窗口
)

// GetLoginACCaptchaThreshold 获取登录的 captcha 阈值
// 优先读 aegis.login.access-control.{connection}.captcha-threshold
// 回退到 aegis.login.access-control.captcha-threshold
func GetLoginACCaptchaThreshold(connection string) int {
	cfg := Cfg()
	perConn := cfg.GetInt("aegis.login.access-control." + connection + ".captcha-threshold")
	if perConn > 0 || cfg.IsSet("aegis.login.access-control."+connection+".captcha-threshold") {
		return perConn
	}
	global := cfg.GetInt("aegis.login.access-control.captcha-threshold")
	if global > 0 || cfg.IsSet("aegis.login.access-control.captcha-threshold") {
		return global
	}
	return DefaultLoginACCaptchaThreshold
}

// GetLoginACFailWindow 获取登录的失败统计窗口
func GetLoginACFailWindow(connection string) time.Duration {
	cfg := Cfg()
	if v := cfg.GetDuration("aegis.login.access-control." + connection + ".fail-window"); v > 0 {
		return v
	}
	if v := cfg.GetDuration("aegis.login.access-control.fail-window"); v > 0 {
		return v
	}
	return DefaultLoginACFailWindow
}

// parseIntMap 解析 map[string]interface{} 为 map[string]int
func parseIntMap(raw map[string]interface{}) map[string]int {
	result := make(map[string]int, len(raw))
	for k, v := range raw {
		switch n := v.(type) {
		case int64:
			result[k] = int(n)
		case float64:
			result[k] = int(n)
		case int:
			result[k] = n
		}
	}
	return result
}

// ==================== SSO 配置 ====================

// SSO 默认值
const (
	DefaultAegisSSOTTL        = 7 * 24 * time.Hour // SSO Token 默认有效期 7 天
	DefaultAegisSSOCookieName = "aegis-sso"        // SSO Cookie 默认名称
)

// GetSSOMasterKey 获取 SSO master key（Base64URL 编码的 48 字节 seed: 16-byte salt + 32-byte key）
// 未配置时返回 nil, nil；配置了但格式错误时返回 nil, error
func GetSSOMasterKey() ([]byte, error) {
	secretStr := Cfg().GetString("sso.master-key")
	if secretStr == "" {
		return nil, nil
	}
	secretBytes, err := base64.RawURLEncoding.DecodeString(secretStr)
	if err != nil {
		return nil, fmt.Errorf("decode sso master key: %w", err)
	}
	if len(secretBytes) != 48 {
		return nil, fmt.Errorf("sso master key must be 48 bytes, got %d", len(secretBytes))
	}
	return secretBytes, nil
}

// GetSSOTTL 获取 SSO Token 有效期
func GetSSOTTL() time.Duration {
	if val := Cfg().GetDuration("sso.ttl"); val > 0 {
		return val
	}
	return DefaultAegisSSOTTL
}

// GetSSOCookieName 获取 SSO Cookie 名称
func GetSSOCookieName() string {
	if name := Cfg().GetString("sso.cookie-name"); name != "" {
		return name
	}
	return DefaultAegisSSOCookieName
}

// GetSSOCookieMaxAge 获取 SSO Cookie MaxAge（秒），与 SSO TTL 保持一致
func GetSSOCookieMaxAge() int {
	return int(GetSSOTTL().Seconds())
}

// ==================== Secret 配置 ====================

// GetSecret 获取 audience 对应的 secret（Base64URL 编码的 32 字节密钥）
func GetSecret(audience string) string {
	return Cfg().GetString("aegis.secrets." + audience)
}

// GetSecretBytes 获取 audience 对应的 secret（解码后的 32 字节密钥）
func GetSecretBytes(audience string) ([]byte, error) {
	secretStr := GetSecret(audience)
	if secretStr == "" {
		return nil, fmt.Errorf("audience %s 的 secret 不存在", audience)
	}
	secretBytes, err := base64.RawURLEncoding.DecodeString(secretStr)
	if err != nil {
		return nil, fmt.Errorf("解码 audience %s 的 secret 失败: %w", audience, err)
	}
	return secretBytes, nil
}
