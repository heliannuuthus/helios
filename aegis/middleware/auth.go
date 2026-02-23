package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	hermesconfig "github.com/heliannuuthus/helios/hermes/config"
	"github.com/heliannuuthus/helios/pkg/aegis/key"
	"github.com/heliannuuthus/helios/pkg/aegis/token"
	"github.com/heliannuuthus/helios/pkg/logger"
)

func tokenPreview(tokenStr string, length int) string {
	if len(tokenStr) <= length {
		return tokenStr
	}
	return tokenStr[:length]
}

func RequireToken(v *token.Interpreter) gin.HandlerFunc {
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

func OptionalToken(v *token.Interpreter) gin.HandlerFunc {
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

// NewHermesKeyStore 创建 Hermes 使用的 KeyStore
func NewHermesKeyStore() (*key.Store, error) {
	masterKey, err := hermesconfig.GetAegisSecretKeyBytes()
	if err != nil {
		return nil, fmt.Errorf("get hermes aegis secret key: %w", err)
	}
	return key.NewStore(key.FetcherFunc(func(ctx context.Context, id string) ([][]byte, error) {
		return [][]byte{masterKey}, nil
	}), nil), nil
}
