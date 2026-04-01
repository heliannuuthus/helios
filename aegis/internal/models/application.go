package models

import (
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/go-json-experiment/json"

	"github.com/heliannuuthus/helios/pkg/logger"
)

// Application 应用（从 proto 转换，不含 GORM 标签）
type Application struct {
	ID                            uint      `json:"_id"`
	DomainID                      string    `json:"domain_id"`
	AppID                         string    `json:"app_id"`
	Name                          string    `json:"name"`
	Description                   *string   `json:"description,omitempty"`
	LogoURL                       *string   `json:"logo_url,omitempty"`
	AllowedRedirectURIs           *string   `json:"allowed_redirect_uris,omitempty"`
	AllowedOrigins                *string   `json:"allowed_origins,omitempty"`
	AllowedLogoutURIs             *string   `json:"allowed_logout_uris,omitempty"`
	IDTokenExpiresIn              uint      `json:"id_token_expires_in"`
	RefreshTokenExpiresIn         uint      `json:"refresh_token_expires_in"`
	RefreshTokenAbsoluteExpiresIn uint      `json:"refresh_token_absolute_expires_in"`
	CreatedAt                     time.Time `json:"created_at"`
	UpdatedAt                     time.Time `json:"updated_at"`
}

// ApplicationWithKey 带密钥的 Application（Main/Keys 不序列化到 API）
type ApplicationWithKey struct {
	Application
	Main []byte   `json:"-"` // 当前主密钥（48 字节 seed）
	Keys [][]byte `json:"-"` // 所有有效密钥
}

// ErrLogoutURINotConfigured allowed_logout_uris 未配置
var ErrLogoutURINotConfigured = errors.New("allowed_logout_uris not configured")

// ==================== Application URI 方法 ====================

// GetAllowedRedirectURIs 解析允许的重定向 URI 列表
func (a *Application) GetAllowedRedirectURIs() []string {
	if a.AllowedRedirectURIs == nil || *a.AllowedRedirectURIs == "" {
		return nil
	}
	var uris []string
	if err := json.Unmarshal([]byte(*a.AllowedRedirectURIs), &uris); err != nil {
		logger.Warnf("[Application] unmarshal allowed redirect uris failed: %v", err)
		return nil
	}
	return uris
}

// ValidateAllowedRedirectURI 验证重定向 URI 是否在允许列表中
func (a *Application) ValidateAllowedRedirectURI(uri string) bool {
	normalizedURI := normalizeURI(uri)
	for _, allowed := range a.GetAllowedRedirectURIs() {
		if normalizeURI(allowed) == normalizedURI {
			return true
		}
	}
	return false
}

// GetAllowedLogoutURIs 解析登出后允许跳转的 URI 列表
func (a *Application) GetAllowedLogoutURIs() []string {
	if a.AllowedLogoutURIs == nil || *a.AllowedLogoutURIs == "" {
		return nil
	}
	var uris []string
	if err := json.Unmarshal([]byte(*a.AllowedLogoutURIs), &uris); err != nil {
		logger.Warnf("[Application] unmarshal allowed logout uris failed: %v", err)
		return nil
	}
	return uris
}

// ValidateAllowedLogoutURI 验证登出后跳转 URI 是否在允许列表中
func (a *Application) ValidateAllowedLogoutURI(uri string) bool {
	normalizedURI := normalizeURI(uri)
	for _, allowed := range a.GetAllowedLogoutURIs() {
		if normalizeURI(allowed) == normalizedURI {
			return true
		}
	}
	return false
}

// ResolveLogoutRedirect 解析登出后跳转 URL
func (a *Application) ResolveLogoutRedirect(returnTo, referer string) (string, error) {
	allowed := a.GetAllowedLogoutURIs()
	if len(allowed) == 0 {
		return "", ErrLogoutURINotConfigured
	}
	try := func(uri string) string {
		u, err := url.Parse(uri)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return ""
		}
		if a.ValidateAllowedLogoutURI(uri) {
			return uri
		}
		return ""
	}
	if returnTo != "" {
		if r := try(returnTo); r != "" {
			return r, nil
		}
	}
	if referer != "" {
		if r := try(referer); r != "" {
			return r, nil
		}
	}
	return "", errors.New("return_to or referer does not match allowed_logout_uris")
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
	if len(allowedOrigins) == 0 {
		return true
	}
	normalizedOrigin := normalizeOrigin(origin)
	for _, allowed := range allowedOrigins {
		if normalizeOrigin(allowed) == normalizedOrigin {
			return true
		}
		if allowed == "*" {
			return true
		}
	}
	return false
}

// ==================== URI 规范化辅助函数 ====================

func normalizeURI(uri string) string {
	u, err := url.Parse(uri)
	if err != nil {
		return uri
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	if (u.Scheme == "https" && u.Port() == "443") ||
		(u.Scheme == "http" && u.Port() == "80") {
		u.Host = u.Hostname()
	}
	u.Path = strings.TrimSuffix(u.Path, "/")
	if u.Path == "" {
		u.Path = "/"
	}
	if u.RawQuery == "" {
		u.ForceQuery = false
	}
	return u.String()
}

func normalizeOrigin(origin string) string {
	u, err := url.Parse(origin)
	if err != nil {
		return strings.ToLower(origin)
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	if (u.Scheme == "https" && u.Port() == "443") ||
		(u.Scheme == "http" && u.Port() == "80") {
		u.Host = u.Hostname()
	}
	return u.Scheme + "://" + u.Host
}
