package config

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// Hermes 配置默认值
const (
	DefaultDBPoolMaxIdleConns = 10
	DefaultDBPoolMaxOpenConns = 30
	DefaultDBPoolConnMaxLife  = "1h"
	DefaultServerHost         = "0.0.0.0"
	DefaultServerPort         = 18000
)

// GetHermesDomainSignKeys 获取域签名密钥列表（原始字符串，逗号分隔）
// 配置格式: "key1,key2,key3" - 第一把是主密钥，其余是旧密钥（用于密钥轮换）
func GetHermesDomainSignKeys(domainID string) []string {
	keyStr := Hermes().GetString(AegisDomains + "." + domainID + ".sign-keys")
	if keyStr == "" {
		return nil
	}
	return strings.Split(keyStr, ",")
}

// GetHermesDomainSignKeysBytes 获取域签名密钥列表（解码后的 32 字节 Ed25519 seed）
// 返回: keys[0] 是主密钥，keys[1:] 是旧密钥（用于密钥轮换）
func GetHermesDomainSignKeysBytes(domainID string) ([][]byte, error) {
	keyStrs := GetHermesDomainSignKeys(domainID)
	if len(keyStrs) == 0 {
		return nil, fmt.Errorf("域 %s 签名密钥不存在", domainID)
	}

	keys := make([][]byte, 0, len(keyStrs))
	for i, keyStr := range keyStrs {
		keyStr = strings.TrimSpace(keyStr)
		if keyStr == "" {
			continue
		}
		keyBytes, err := base64.RawURLEncoding.DecodeString(keyStr)
		if err != nil {
			return nil, fmt.Errorf("解码签名密钥[%d]失败: %w", i, err)
		}
		keys = append(keys, keyBytes)
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("域 %s 签名密钥不存在", domainID)
	}

	return keys, nil
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

// GetIrisAegisSecretKeyBytes 获取 Iris 服务解密密钥（32 字节 raw key）
// 配置格式: base64url 编码的 32 字节密钥
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

	if len(secretBytes) != 32 {
		return nil, fmt.Errorf("iris aegis.secret-key 长度错误: 期望 32 字节, 实际 %d 字节", len(secretBytes))
	}

	return secretBytes, nil
}

// GetHermesAegisSecretKey 获取 Hermes 服务解密密钥（原始字符串）
func GetHermesAegisSecretKey() string {
	return Hermes().GetString(AegisSecretKey)
}

// GetHermesAegisSecretKeyBytes 获取 Hermes 服务解密密钥（32 字节 raw key）
// 配置格式: base64url 编码的 32 字节密钥
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

	if len(secretBytes) != 32 {
		return nil, fmt.Errorf("hermes aegis.secret-key 长度错误: 期望 32 字节, 实际 %d 字节", len(secretBytes))
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
