package config

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// AuthConfig Auth 配置
type AuthConfig struct {
	Issuer  string                  `mapstructure:"issuer"`
	Domains map[string]DomainConfig `mapstructure:"domains"`
}

// DomainConfig 域配置
type DomainConfig struct {
	Name        string `mapstructure:"name"`
	Description string `mapstructure:"description"`
	SignKey     string `mapstructure:"sign_key"`
	EncryptKey  string `mapstructure:"encrypt_key"`
}

var authConfig *AuthConfig

// InitAuthConfig 初始化 Auth 配置
func InitAuthConfig() error {
	v := V()

	authConfig = &AuthConfig{}
	if err := v.UnmarshalKey("auth", authConfig); err != nil {
		return fmt.Errorf("解析 auth 配置失败: %w", err)
	}

	return nil
}

// GetAuthConfig 获取 Auth 配置
func GetAuthConfig() *AuthConfig {
	if authConfig == nil {
		_ = InitAuthConfig() // 忽略初始化错误，使用默认值
	}
	return authConfig
}

// GetIssuer 获取 Issuer
func GetIssuer() string {
	cfg := GetAuthConfig()
	if cfg == nil {
		return "https://auth.heliannuuthus.com/api"
	}
	return cfg.Issuer
}

// GetDomainConfig 获取域配置
func GetDomainConfig(domainID string) (*DomainConfig, error) {
	cfg := GetAuthConfig()
	if cfg == nil {
		return nil, fmt.Errorf("auth 配置未初始化")
	}

	domainConfig, ok := cfg.Domains[domainID]
	if !ok {
		return nil, fmt.Errorf("域 %s 配置不存在", domainID)
	}

	if domainConfig.SignKey == "" || domainConfig.EncryptKey == "" {
		return nil, fmt.Errorf("域 %s 配置不完整", domainID)
	}

	return &domainConfig, nil
}

// GetDomainSignKey 获取域签名密钥
func GetDomainSignKey(domainID string) ([]byte, error) {
	domainConfig, err := GetDomainConfig(domainID)
	if err != nil {
		return nil, err
	}

	// 解析密钥格式：算法:base64密钥
	parts := strings.SplitN(domainConfig.SignKey, ":", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("无效的签名密钥格式")
	}

	keyBytes, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("解码签名密钥失败: %w", err)
	}

	return keyBytes, nil
}

// GetDomainEncryptKey 获取域加密密钥
func GetDomainEncryptKey(domainID string) ([]byte, error) {
	domainConfig, err := GetDomainConfig(domainID)
	if err != nil {
		return nil, err
	}

	// 解析密钥格式：算法:base64密钥
	parts := strings.SplitN(domainConfig.EncryptKey, ":", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("无效的加密密钥格式")
	}

	keyBytes, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("解码加密密钥失败: %w", err)
	}

	return keyBytes, nil
}
