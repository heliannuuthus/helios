package validation

import (
	"fmt"
	"net/url"
	"strings"
)

// 禁止的 URI scheme（防止开放重定向、XSS 等）
var forbiddenSchemes = map[string]bool{
	"javascript": true,
	"data":       true,
	"file":       true,
	"vbscript":   true,
}

const maxURILen = 512

// ValidateRedirectURI 校验重定向 URI：合法 URL、https（localhost 允许 http）、禁止危险 scheme
func ValidateRedirectURI(uri string) error {
	uri = strings.TrimSpace(uri)
	if uri == "" {
		return fmt.Errorf("重定向 URI 不能为空")
	}
	if len(uri) > maxURILen {
		return fmt.Errorf("重定向 URI 长度不能超过 %d 字符", maxURILen)
	}
	u, err := url.Parse(uri)
	if err != nil {
		return fmt.Errorf("重定向 URI 格式无效: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("重定向 URI 必须包含 scheme 和 host")
	}
	if forbiddenSchemes[strings.ToLower(u.Scheme)] {
		return fmt.Errorf("重定向 URI 不允许使用 %s 协议", u.Scheme)
	}
	if !isSecureOrigin(u) {
		return fmt.Errorf("重定向 URI 必须使用 https（localhost 除外）")
	}
	return nil
}

// ValidateAllowedOrigin 校验跨域源：合法 origin 格式（scheme://host[:port]）、https（localhost 除外）
func ValidateAllowedOrigin(origin string) error {
	origin = strings.TrimSpace(origin)
	if origin == "" {
		return fmt.Errorf("跨域源不能为空")
	}
	if len(origin) > maxURILen {
		return fmt.Errorf("跨域源长度不能超过 %d 字符", maxURILen)
	}
	u, err := url.Parse(origin)
	if err != nil {
		return fmt.Errorf("跨域源格式无效: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("跨域源必须包含 scheme 和 host")
	}
	if u.Path != "" && u.Path != "/" {
		return fmt.Errorf("跨域源不应包含路径（仅 scheme://host[:port]）")
	}
	if forbiddenSchemes[strings.ToLower(u.Scheme)] {
		return fmt.Errorf("跨域源不允许使用 %s 协议", u.Scheme)
	}
	if !isSecureOrigin(u) {
		return fmt.Errorf("跨域源必须使用 https（localhost 除外）")
	}
	return nil
}

// ValidateLogoutURI 校验登出后跳转 URI，规则同重定向 URI
func ValidateLogoutURI(uri string) error {
	return ValidateRedirectURI(uri)
}

// isSecureOrigin 判断是否为安全 origin：https 或 localhost/127.0.0.1 的 http
func isSecureOrigin(u *url.URL) bool {
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	if scheme == "https" {
		return true
	}
	if scheme == "http" && (host == "localhost" || host == "127.0.0.1") {
		return true
	}
	return false
}

// ValidateRedirectURIs 校验重定向 URI 列表
func ValidateRedirectURIs(uris []string) error {
	for i, uri := range uris {
		if err := ValidateRedirectURI(uri); err != nil {
			return fmt.Errorf("第 %d 个重定向 URI: %w", i+1, err)
		}
	}
	return nil
}

// ValidateAllowedOrigins 校验跨域源列表
func ValidateAllowedOrigins(origins []string) error {
	for i, origin := range origins {
		if err := ValidateAllowedOrigin(origin); err != nil {
			return fmt.Errorf("第 %d 个跨域源: %w", i+1, err)
		}
	}
	return nil
}

// ValidateLogoutURIs 校验登出后跳转 URI 列表
func ValidateLogoutURIs(uris []string) error {
	for i, uri := range uris {
		if err := ValidateLogoutURI(uri); err != nil {
			return fmt.Errorf("第 %d 个登出 URI: %w", i+1, err)
		}
	}
	return nil
}
