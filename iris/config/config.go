package config

import (
	"encoding/base64"
	"fmt"

	baseconfig "github.com/heliannuuthus/helios/pkg/config"
)

// Cfg 返回 Iris 配置单例
func Cfg() *baseconfig.Cfg {
	return baseconfig.Iris()
}

// GetAegisAudience 获取 Iris 服务 audience（用于 token 验证）
func GetAegisAudience() string {
	audience := Cfg().GetString("aegis.audience")
	if audience == "" {
		return "iris"
	}
	return audience
}

// GetAegisSecretKey 获取 Iris 服务解密密钥（原始字符串）
func GetAegisSecretKey() string {
	return Cfg().GetString("aegis.secret-key")
}

// GetAegisSecretKeyBytes 获取 Iris 服务密钥（48 字节 seed: 16-byte salt + 32-byte key）
func GetAegisSecretKeyBytes() ([]byte, error) {
	secretStr := GetAegisSecretKey()
	if secretStr == "" {
		return nil, fmt.Errorf("iris aegis.secret-key 未配置")
	}
	secretBytes, err := base64.RawURLEncoding.DecodeString(secretStr)
	if err != nil {
		return nil, fmt.Errorf("解码 iris aegis.secret-key 失败: %w", err)
	}
	if len(secretBytes) != 48 {
		return nil, fmt.Errorf("iris aegis.secret-key 长度错误: 期望 48 字节 seed, 实际 %d 字节", len(secretBytes))
	}
	return secretBytes, nil
}
