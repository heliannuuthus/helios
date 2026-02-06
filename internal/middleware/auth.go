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
	"github.com/heliannuuthus/helios/pkg/logger"
)

func tokenPreview(tokenStr string, length int) string {
	if len(tokenStr) <= length {
		return tokenStr
	}
	return tokenStr[:length]
}

func RequireToken(v *interpreter.Interpreter) gin.HandlerFunc {
	return func(c *gin.Context) {
		authorization := c.GetHeader("Authorization")
		if authorization == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"detail": "unauthorized"})
			return
		}
		tokenStr := authorization
		if strings.HasPrefix(authorization, "Bearer ") {
			tokenStr = authorization[7:]
		}
		identity, err := v.Interpret(c.Request.Context(), tokenStr)
		if err != nil {
			logger.Warnf("[Auth] Token failed - Path: %s, Error: %v, Preview: %s...", c.Request.URL.Path, err, tokenPreview(tokenStr, 20))
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"detail": "unauthorized"})
			return
		}
		c.Set("user", identity)
		c.Next()
	}
}

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
			c.Set("user", identity)
		}
		c.Next()
	}
}

func NewHermesKeyProvider() (keys.KeyProvider, error) {
	masterKey, err := config.GetHermesAegisSecretKeyBytes()
	if err != nil {
		return nil, fmt.Errorf("get hermes aegis secret key: %w", err)
	}
	keyStr := string(masterKey)
	return keys.KeyProviderFunc(func(ctx context.Context, id string) (map[string]struct{}, error) {
		return map[string]struct{}{keyStr: {}}, nil
	}), nil
}
