package config

import (
	"encoding/base64"
	"fmt"
)

// Hermes 配置默认值
const (
	DefaultDBPoolMaxIdleConns = 10
	DefaultDBPoolMaxOpenConns = 30
	DefaultDBPoolConnMaxLife  = "1h"
	DefaultServerHost         = "0.0.0.0"
	DefaultServerPort         = 18000
)

// GetHermesDomainSignKey 获取域签名密钥
func GetHermesDomainSignKey(domainID string) string {
	return Hermes().GetString(AegisDomains + "." + domainID + ".sign-key")
}

// GetHermesAegisAudience 获取 Hermes 服务 audience（用于 token 验证）
func GetHermesAegisAudience() string {
	audience := Hermes().GetString(AegisAudience)
	if audience == "" {
		return "hermes" // 默认值
	}
	return audience
}

// GetIrisAegisAudience 获取 Iris 服务 audience（用于 token 验证）
func GetIrisAegisAudience() string {
	audience := Iris().GetString(AegisAudience)
	if audience == "" {
		return "iris" // 默认值
	}
	return audience
}

// GetIrisAegisSecretKey 获取 Iris 服务解密密钥（原始字符串）
func GetIrisAegisSecretKey() string {
	return Iris().GetString(AegisSecretKey)
}

// GetIrisAegisSecretKeyBytes 获取 Iris 服务解密密钥（解码后的 JWK JSON 字节）
func GetIrisAegisSecretKeyBytes() ([]byte, error) {
	secretStr := GetIrisAegisSecretKey()
	if secretStr == "" {
		return nil, fmt.Errorf("iris aegis.secret-key 未配置")
	}

	// base64url 解码
	secretBytes, err := base64.RawURLEncoding.DecodeString(secretStr)
	if err != nil {
		return nil, fmt.Errorf("解码 iris aegis.secret-key 失败: %w", err)
	}

	return secretBytes, nil
}

// GetHermesAegisSecretKey 获取 Hermes 服务解密密钥（原始字符串）
func GetHermesAegisSecretKey() string {
	return Hermes().GetString(AegisSecretKey)
}

// GetHermesAegisSecretKeyBytes 获取 Hermes 服务解密密钥（解码后的 JWK JSON 字节）
func GetHermesAegisSecretKeyBytes() ([]byte, error) {
	secretStr := GetHermesAegisSecretKey()
	if secretStr == "" {
		return nil, fmt.Errorf("hermes aegis.secret-key 未配置")
	}

	// base64url 解码
	secretBytes, err := base64.RawURLEncoding.DecodeString(secretStr)
	if err != nil {
		return nil, fmt.Errorf("解码 hermes aegis.secret-key 失败: %w", err)
	}

	return secretBytes, nil
}

// GetDBEncKeyRaw 获取数据库加密密钥的原始字节
// 配置格式: 标准 Base64 编码的 32 字节 AES-256 密钥
// 用于加密用户手机号、服务密钥等敏感数据
func GetDBEncKeyRaw() ([]byte, error) {
	keyStr := Hermes().GetString("db.enc-key")
	if keyStr == "" {
		return nil, fmt.Errorf("db.enc-key 未配置")
	}

	// 标准 Base64 解码
	key, err := base64.StdEncoding.DecodeString(keyStr)
	if err != nil {
		return nil, fmt.Errorf("解码数据库加密密钥失败: %w", err)
	}

	if len(key) != 32 {
		return nil, fmt.Errorf("数据库加密密钥长度错误: 期望 32 字节, 实际 %d 字节", len(key))
	}

	return key, nil
}
