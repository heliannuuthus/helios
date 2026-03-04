package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	hermesconfig "github.com/heliannuuthus/helios/hermes/config"
	"github.com/heliannuuthus/helios/pkg/aegis/key"
	"github.com/heliannuuthus/helios/pkg/aegis/web"
	"github.com/heliannuuthus/helios/pkg/logger"
)

func RequireToken(v *web.Interpreter) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenStr := extractBearer(c.GetHeader("Authorization"))
		if tokenStr == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"detail": "unauthorized"})
			return
		}
		identity, err := v.Interpret(c.Request.Context(), tokenStr)
		if err != nil {
			logger.Warnf("[Auth] Token failed - Path: %s, Error: %v, Preview: %s...", c.Request.URL.Path, err, tokenPreview(tokenStr, 20))
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"detail": "unauthorized"})
			return
		}
		tc, err := web.NewTokenContext(identity)
		if err != nil {
			logger.Warnf("[Auth] TokenContext failed - Path: %s, Error: %v", c.Request.URL.Path, err)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"detail": "unauthorized"})
			return
		}
		c.Set(string(web.ClaimsKey), tc)
		c.Next()
	}
}

func OptionalToken(v *web.Interpreter) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenStr := extractBearer(c.GetHeader("Authorization"))
		if tokenStr == "" {
			c.Next()
			return
		}
		identity, err := v.Interpret(c.Request.Context(), tokenStr)
		if err != nil || identity == nil {
			c.Next()
			return
		}
		tc, err := web.NewTokenContext(identity)
		if err != nil {
			c.Next()
			return
		}
		c.Set(string(web.ClaimsKey), tc)
		c.Next()
	}
}

// NewHermesKeyProvider 创建 Hermes 使用的密钥 Provider
func NewHermesKeyProvider() (key.Provider, error) {
	masterKey, err := hermesconfig.GetAegisSecretKeyBytes()
	if err != nil {
		return nil, fmt.Errorf("get hermes aegis secret key: %w", err)
	}
	return key.LoadKeyFunc(func(_ context.Context, _ string) ([]byte, error) {
		return masterKey, nil
	}), nil
}

func tokenPreview(tokenStr string, length int) string {
	if len(tokenStr) <= length {
		return tokenStr
	}
	return tokenStr[:length]
}

func extractBearer(authorization string) string {
	if len(authorization) > 7 && strings.EqualFold(authorization[:7], "Bearer ") {
		return authorization[7:]
	}
	return ""
}
