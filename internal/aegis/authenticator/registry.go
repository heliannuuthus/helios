// Package authenticator provides unified authenticator registry for all connection types.
package authenticator

import (
	"context"
	"sync"

	"github.com/heliannuuthus/helios/internal/aegis/authenticator/captcha"
	"github.com/heliannuuthus/helios/internal/aegis/authenticator/idp"
	"github.com/heliannuuthus/helios/internal/aegis/authenticator/webauthn"
)

// Registry 全局认证器注册表
// 统一管理所有 Connection 类型：IDP、WebAuthn/Passkey、TOTP、Captcha 等
type Registry struct {
	mu sync.RWMutex

	// IDP Providers（github, google, user, oper, wechat:mp, tt:mp, alipay:mp, passkey...）
	idpProviders map[string]idp.Provider

	// WebAuthn 服务（MFA/Passkey 共用底层）
	webauthnSvc *webauthn.Service

	// Captcha 验证器
	captchaVerifier captcha.Verifier

	// TOTP 验证器
	totpVerifier TOTPVerifier
}

// TOTPVerifier TOTP 验证接口
type TOTPVerifier interface {
	Verify(ctx context.Context, userID, code string) (bool, error)
}

// RegistryConfig Registry 构造配置
type RegistryConfig struct {
	WebAuthn *webauthn.Service
	Captcha  captcha.Verifier
	TOTP     TOTPVerifier
}

// NewRegistry 创建全局注册表
func NewRegistry(cfg *RegistryConfig) *Registry {
	r := &Registry{
		idpProviders: make(map[string]idp.Provider),
	}
	if cfg != nil {
		r.webauthnSvc = cfg.WebAuthn
		r.captchaVerifier = cfg.Captcha
		r.totpVerifier = cfg.TOTP
	}
	return r
}

// ==================== IDP Provider 注册 ====================

// RegisterIDP 注册 IDP Provider
func (r *Registry) RegisterIDP(p idp.Provider) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.idpProviders[p.Type()] = p
}

// GetIDP 获取 IDP Provider
func (r *Registry) GetIDP(idpType string) (idp.Provider, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.idpProviders[idpType]
	return p, ok
}

// HasIDP 检查是否已注册指定类型的 IDP Provider
func (r *Registry) HasIDP(idpType string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.idpProviders[idpType]
	return ok
}

// ListIDPs 列出所有已注册的 IDP 类型
func (r *Registry) ListIDPs() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	types := make([]string, 0, len(r.idpProviders))
	for t := range r.idpProviders {
		types = append(types, t)
	}
	return types
}

// ==================== WebAuthn 服务 ====================

// GetWebAuthn 获取 WebAuthn 服务
func (r *Registry) GetWebAuthn() *webauthn.Service {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.webauthnSvc
}

// HasWebAuthn 检查 WebAuthn 是否可用
func (r *Registry) HasWebAuthn() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.webauthnSvc != nil
}

// ==================== Captcha 验证器 ====================

// GetCaptcha 获取 Captcha 验证器
func (r *Registry) GetCaptcha() captcha.Verifier {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.captchaVerifier
}

// HasCaptcha 检查 Captcha 是否可用
func (r *Registry) HasCaptcha() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.captchaVerifier != nil
}

// ==================== TOTP 验证器 ====================

// GetTOTP 获取 TOTP 验证器
func (r *Registry) GetTOTP() TOTPVerifier {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.totpVerifier
}

// HasTOTP 检查 TOTP 是否可用
func (r *Registry) HasTOTP() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.totpVerifier != nil
}

// ==================== 统一查询 ====================

// Supports 检查是否支持指定的 connection 类型
func (r *Registry) Supports(connection string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if _, ok := r.idpProviders[connection]; ok {
		return true
	}

	if (connection == "webauthn" || connection == "passkey") && r.webauthnSvc != nil {
		return true
	}

	if connection == "totp" && r.totpVerifier != nil {
		return true
	}

	if len(connection) > 8 && connection[:8] == "captcha:" && r.captchaVerifier != nil {
		return true
	}

	return false
}

// Summary 返回注册表摘要信息
func (r *Registry) Summary() map[string]any {
	r.mu.RLock()
	defer r.mu.RUnlock()

	idps := make([]string, 0, len(r.idpProviders))
	for t := range r.idpProviders {
		idps = append(idps, t)
	}

	return map[string]any{
		"idp_count": len(r.idpProviders),
		"idps":      idps,
		"webauthn":  r.webauthnSvc != nil,
		"captcha":   r.captchaVerifier != nil,
		"totp":      r.totpVerifier != nil,
	}
}
