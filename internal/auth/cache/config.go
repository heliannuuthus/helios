package cache

import (
	"time"

	"github.com/heliannuuthus/helios/internal/config"
)

// 配置路径常量
const (
	configPrefix = "auth.cache."
)

// 默认过期时间
const (
	defaultAuthFlowExpiresIn     = 10 * time.Minute
	defaultAuthCodeExpiresIn     = 5 * time.Minute
	defaultOTPExpiresIn          = 5 * time.Minute
	defaultRefreshTokenExpiresIn = 7 * 24 * time.Hour
)

// GetAuthFlowExpiresIn 获取 AuthFlow 过期时间（支持热更新）
func GetAuthFlowExpiresIn() time.Duration {
	return getExpiresIn("auth_flow", defaultAuthFlowExpiresIn)
}

// GetAuthCodeExpiresIn 获取 AuthCode 过期时间（支持热更新）
func GetAuthCodeExpiresIn() time.Duration {
	return getExpiresIn("auth_code", defaultAuthCodeExpiresIn)
}

// GetOTPExpiresIn 获取 OTP 过期时间（支持热更新）
func GetOTPExpiresIn() time.Duration {
	return getExpiresIn("otp", defaultOTPExpiresIn)
}

// GetRefreshTokenExpiresIn 获取 RefreshToken 过期时间（支持热更新）
func GetRefreshTokenExpiresIn() time.Duration {
	return getExpiresIn("refresh_token", defaultRefreshTokenExpiresIn)
}

// getExpiresIn 通用获取过期时间方法
func getExpiresIn(cacheType string, defaultVal time.Duration) time.Duration {
	key := configPrefix + cacheType + ".expires_in"
	duration := config.Auth().GetDuration(key)
	if duration <= 0 {
		return defaultVal
	}
	return duration
}

// GetKeyPrefix 获取缓存 key 前缀（支持热更新）
func GetKeyPrefix(cacheType string) string {
	// 先尝试从配置读取
	key := configPrefix + cacheType + ".prefix"
	if prefix := config.Auth().GetString(key); prefix != "" {
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
		// 本地缓存（实体数据）
		"domain":                       "domain:",
		"application":                  "app:",
		"service":                      "svc:",
		"user":                         "user:",
		"application-service-relation": "app-svc-rel:",
	}

	if prefix, ok := defaultPrefixes[cacheType]; ok {
		return prefix
	}

	return cacheType + ":"
}
