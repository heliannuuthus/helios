package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/heliannuuthus/helios/internal/config"
	"github.com/heliannuuthus/helios/pkg/aegis/interpreter"
	"github.com/heliannuuthus/helios/pkg/aegis/keys"
	"github.com/heliannuuthus/helios/pkg/aegis/token"
	"github.com/heliannuuthus/helios/pkg/logger"
)

// AuthMiddleware 认证中间件（可选认证）
// Deprecated: 使用 OptionalToken 替代
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Warnf("[Auth] AuthMiddleware is deprecated, use OptionalToken instead")
		c.Next()
	}
}

// RequireAuth 要求认证中间件
// Deprecated: 使用 RequireToken 替代
func RequireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Warnf("[Auth] RequireAuth is deprecated, use RequireToken instead")
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"detail": "deprecated middleware"})
	}
}

// tokenPreview 生成 token 预览（避免在日志中暴露完整 token）
func tokenPreview(tokenStr string, length int) string {
	if len(tokenStr) <= length {
		return tokenStr
	}
	return tokenStr[:length]
}

// RequireToken 新版本认证中间件（使用 interpreter.Interpreter）
func RequireToken(v *interpreter.Interpreter) gin.HandlerFunc {
	return func(c *gin.Context) {
		authorization := c.GetHeader("Authorization")
		if authorization == "" {
			logger.Debugf("[Auth] 请求未携带 Authorization 头 - Path: %s, IP: %s", c.Request.URL.Path, c.ClientIP())
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"detail": "未登录或登录已过期"})
			return
		}

		tokenStr := authorization
		if strings.HasPrefix(authorization, "Bearer ") {
			tokenStr = authorization[7:]
		}

		identity, err := v.Interpret(c.Request.Context(), tokenStr)
		if err != nil {
			logger.Warnf("[Auth] Token 验证失败 - Path: %s, IP: %s, Error: %v, TokenPreview: %s...",
				c.Request.URL.Path,
				c.ClientIP(),
				err,
				tokenPreview(tokenStr, 20))
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"detail": "未登录或登录已过期"})
			return
		}

		openID := getOpenIDFromToken(identity)
		logger.Infof("[Auth] 认证成功 - Path: %s, OpenID: %s", c.Request.URL.Path, openID)
		c.Set("user", identity)
		c.Next()
	}
}

// OptionalToken 新版本可选认证中间件（使用 interpreter.Interpreter）
func OptionalToken(v *interpreter.Interpreter) gin.HandlerFunc {
	return func(c *gin.Context) {
		authorization := c.GetHeader("Authorization")
		if authorization == "" {
			c.Next()
			return
		}

		tokenStr := authorization
		if strings.HasPrefix(authorization, "Bearer ") {
			tokenStr = authorization[7:]
		}

		identity, err := v.Interpret(c.Request.Context(), tokenStr)
		if err == nil && identity != nil {
			openID := getOpenIDFromToken(identity)
			logger.Infof("[Auth] 可选认证成功 - Path: %s, OpenID: %s", c.Request.URL.Path, openID)
			c.Set("user", identity)
		}

		c.Next()
	}
}

// getOpenIDFromToken 从 Token 中提取 OpenID
func getOpenIDFromToken(t token.Token) string {
	if uat, ok := token.AsUAT(t); ok && uat.HasUser() {
		return uat.GetOpenID()
	}
	return ""
}

// NewHermesKeyProvider 创建基于 Hermes 配置的密钥提供者
// 从 aegis.secret-key 读取 32 字节主密钥
func NewHermesKeyProvider() (keys.KeyProvider, error) {
	// 配置已直接返回 32 字节 raw key
	masterKey, err := config.GetHermesAegisSecretKeyBytes()
	if err != nil {
		return nil, fmt.Errorf("get hermes aegis secret key: %w", err)
	}

	// 返回一个简单的 KeyProvider，忽略 id 参数，总是返回同一个主密钥
	// string(masterKey) 将 []byte 转为 string 用于 map key
	keyStr := string(masterKey)
	return keys.KeyProviderFunc(func(ctx context.Context, id string) (map[string]struct{}, error) {
		return map[string]struct{}{keyStr: {}}, nil
	}), nil
}
