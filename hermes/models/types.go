package models

import (
	"net/url"
	"strings"

	"github.com/go-json-experiment/json"

	"github.com/heliannuuthus/helios/pkg/logger"
)

// ApplicationWithKey 带密钥的 Application（Main/Keys 不序列化到 API）
type ApplicationWithKey struct {
	Application
	Main []byte   `json:"-"` // 当前主密钥（48 字节 seed）
	Keys [][]byte `json:"-"` // 所有有效密钥（包括主密钥和轮换中的旧密钥）
}

// GetRedirectURIs 解析重定向 URI 列表
func (a *Application) GetRedirectURIs() []string {
	if a.RedirectURIs == nil || *a.RedirectURIs == "" {
		return nil
	}
	var uris []string
	if err := json.Unmarshal([]byte(*a.RedirectURIs), &uris); err != nil {
		logger.Warnf("[Application] unmarshal redirect uris failed: %v", err)
		return nil
	}
	return uris
}

// ValidateRedirectURI 验证重定向 URI（规范化后比较）
func (a *Application) ValidateRedirectURI(uri string) bool {
	normalizedURI := normalizeURI(uri)

	for _, allowed := range a.GetRedirectURIs() {
		if normalizeURI(allowed) == normalizedURI {
			return true
		}
	}
	return false
}

// GetAllowedOrigins 解析允许的跨域源列表
func (a *Application) GetAllowedOrigins() []string {
	if a.AllowedOrigins == nil || *a.AllowedOrigins == "" {
		return nil
	}
	var origins []string
	if err := json.Unmarshal([]byte(*a.AllowedOrigins), &origins); err != nil {
		logger.Warnf("[Application] unmarshal allowed origins failed: %v", err)
		return nil
	}
	return origins
}

// ValidateOrigin 验证请求来源是否允许
func (a *Application) ValidateOrigin(origin string) bool {
	allowedOrigins := a.GetAllowedOrigins()
	// 如果未配置，则不限制
	if len(allowedOrigins) == 0 {
		return true
	}

	normalizedOrigin := normalizeOrigin(origin)
	for _, allowed := range allowedOrigins {
		if normalizeOrigin(allowed) == normalizedOrigin {
			return true
		}
		// 支持通配符 *
		if allowed == "*" {
			return true
		}
	}
	return false
}

// ServiceWithKey 带密钥的 Service（Main/Keys 不序列化到 API）
type ServiceWithKey struct {
	Service
	Main []byte   `json:"-"` // 当前主密钥（48 字节 seed）
	Keys [][]byte `json:"-"` // 所有有效密钥（包括主密钥和轮换中的旧密钥）
}

// GetRequiredIdentities 解析访问该服务需要绑定的身份类型
func (s *Service) GetRequiredIdentities() []string {
	if s.RequiredIdentities == nil || *s.RequiredIdentities == "" {
		return nil
	}
	var identities []string
	if err := json.Unmarshal([]byte(*s.RequiredIdentities), &identities); err != nil {
		logger.Warnf("[Service] unmarshal required identities failed: %v", err)
		return nil
	}
	return identities
}

// Domain 域（元数据与允许的 IDP 来自数据库，签名密钥来自配置/密钥服务）
type Domain struct {
	DomainID    string   `json:"domain_id"`    // 域标识：consumer/platform
	Name        string   `json:"name"`         // 域名称
	Description *string  `json:"description"`  // 域描述
	AllowedIDPs []string `json:"allowed_idps"` // 该域允许的 IDP 类型，应用添加 IDP 时只能从此列表选
}

// DomainWithKey 带签名密钥的 Domain（Main/Keys 不序列化到 API）
type DomainWithKey struct {
	Domain
	Main []byte   `json:"-"` // 当前主密钥（48 字节 seed，用于签发新 token）
	Keys [][]byte `json:"-"` // 所有有效密钥（包括主密钥和轮换中的旧密钥，用于验证）
}

// ==================== URI 规范化辅助函数 ====================

// normalizeURI 规范化 URI
// - 统一小写 scheme 和 host
// - 移除默认端口（80/443）
// - 移除末尾斜杠（除了根路径）
// - 移除空的 query string
func normalizeURI(uri string) string {
	u, err := url.Parse(uri)
	if err != nil {
		return uri
	}

	// 小写 scheme 和 host
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)

	// 移除默认端口
	if (u.Scheme == "https" && u.Port() == "443") ||
		(u.Scheme == "http" && u.Port() == "80") {
		u.Host = u.Hostname()
	}

	// 移除末尾斜杠（除了根路径）
	u.Path = strings.TrimSuffix(u.Path, "/")
	if u.Path == "" {
		u.Path = "/"
	}

	// 移除空 query
	if u.RawQuery == "" {
		u.ForceQuery = false
	}

	return u.String()
}

// normalizeOrigin 规范化 Origin（只保留 scheme + host）
func normalizeOrigin(origin string) string {
	u, err := url.Parse(origin)
	if err != nil {
		return strings.ToLower(origin)
	}

	// 小写 scheme 和 host
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)

	// 移除默认端口
	if (u.Scheme == "https" && u.Port() == "443") ||
		(u.Scheme == "http" && u.Port() == "80") {
		u.Host = u.Hostname()
	}

	// Origin 只包含 scheme + host
	return u.Scheme + "://" + u.Host
}
