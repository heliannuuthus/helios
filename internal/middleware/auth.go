package middleware

import (
	"net/http"
	"strings"

	"choosy-backend/internal/services"

	"github.com/gin-gonic/gin"
)

// AuthMiddleware 认证中间件（可选认证）
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authorization := c.GetHeader("Authorization")
		if authorization == "" {
			c.Next()
			return
		}

		// 移除 Bearer 前缀
		token := authorization
		if strings.HasPrefix(authorization, "Bearer ") {
			token = authorization[7:]
		}

		identity, err := services.VerifyAccessToken(token)
		if err == nil && identity != nil {
			c.Set("user", identity)
		}

		c.Next()
	}
}

// RequireAuth 要求认证中间件
func RequireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		authorization := c.GetHeader("Authorization")
		if authorization == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"detail": "未登录或登录已过期"})
			return
		}

		// 移除 Bearer 前缀
		token := authorization
		if strings.HasPrefix(authorization, "Bearer ") {
			token = authorization[7:]
		}

		identity, err := services.VerifyAccessToken(token)
		if err != nil || identity == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"detail": "未登录或登录已过期"})
			return
		}

		c.Set("user", identity)
		c.Next()
	}
}

