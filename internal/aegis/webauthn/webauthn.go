// Package webauthn provides WebAuthn/Passkey authentication support.
package webauthn

import (
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/heliannuuthus/helios/internal/config"
)

// Config WebAuthn 配置
type Config struct {
	RPID          string   // Relying Party ID（域名）
	RPDisplayName string   // 显示名称
	RPOrigins     []string // 允许的来源
}

var (
	webAuthnInstance *webauthn.WebAuthn
	webAuthnConfig   *Config
)

// Init 初始化 WebAuthn
func Init() error {
	cfg := config.Aegis()

	// 从配置读取 WebAuthn 设置
	rpID := cfg.GetString("mfa.webauthn.rp-id")
	if rpID == "" {
		rpID = "aegis.heliannuuthus.com" // 默认值
	}

	rpDisplayName := cfg.GetString("mfa.webauthn.rp-display-name")
	if rpDisplayName == "" {
		rpDisplayName = "Helios Auth"
	}

	// 允许的来源
	rpOrigins := cfg.GetStringSlice("mfa.webauthn.rp-origins")
	if len(rpOrigins) == 0 {
		rpOrigins = []string{"https://" + rpID}
	}

	webAuthnConfig = &Config{
		RPID:          rpID,
		RPDisplayName: rpDisplayName,
		RPOrigins:     rpOrigins,
	}

	// 创建 WebAuthn 实例
	wconfig := &webauthn.Config{
		RPID:          webAuthnConfig.RPID,
		RPDisplayName: webAuthnConfig.RPDisplayName,
		RPOrigins:     webAuthnConfig.RPOrigins,
	}

	var err error
	webAuthnInstance, err = webauthn.New(wconfig)
	if err != nil {
		return err
	}

	return nil
}

// GetInstance 获取 WebAuthn 实例
func GetInstance() *webauthn.WebAuthn {
	return webAuthnInstance
}

// GetConfig 获取 WebAuthn 配置
func GetConfig() *Config {
	return webAuthnConfig
}

// IsEnabled 检查 WebAuthn 是否启用
func IsEnabled() bool {
	return config.Aegis().GetBool("mfa.webauthn.enabled")
}
