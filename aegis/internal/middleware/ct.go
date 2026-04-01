package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	pkgtoken "github.com/heliannuuthus/aegis-go/utilities/token"

	"github.com/heliannuuthus/helios/aegis/internal/consts"
	"github.com/heliannuuthus/helios/aegis/internal/token"
)

// Middleware 认证中间件（用于验证 CT）
type Middleware struct {
	tokenSvc *token.Service
}

// NewMiddleware 创建中间件
func NewMiddleware(tokenSvc *token.Service) *Middleware {
	return &Middleware{
		tokenSvc: tokenSvc,
	}
}

// RequireClientAuth 要求客户端认证（验证 CT）
func (m *Middleware) RequireClientAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenStr := m.extractToken(c)
		if tokenStr == "" {
			c.Header("WWW-Authenticate", pkgtoken.TokenTypeBearer)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":             "invalid_token",
				"error_description": "missing client token",
			})
			return
		}

		t, err := m.tokenSvc.Verify(c.Request.Context(), tokenStr)
		if err != nil {
			c.Header("WWW-Authenticate", pkgtoken.TokenTypeBearer+` error="invalid_token"`)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":             "invalid_token",
				"error_description": err.Error(),
			})
			return
		}
		claims, ok := t.(*pkgtoken.ClientToken)
		if !ok {
			c.Header("WWW-Authenticate", pkgtoken.TokenTypeBearer+` error="invalid_token"`)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":             "invalid_token",
				"error_description": "expected CT token",
			})
			return
		}

		c.Set("client_claims", claims)
		c.Next()
	}
}

func (*Middleware) extractToken(c *gin.Context) string {
	auth := c.GetHeader(consts.HeaderAuthorization)
	if strings.HasPrefix(auth, consts.BearerPrefix) {
		return auth[7:]
	}
	return ""
}

// GetClientClaims 从上下文获取客户端信息
func GetClientClaims(c *gin.Context) *pkgtoken.ClientToken {
	if claims, exists := c.Get("client_claims"); exists {
		if ct, ok := claims.(*pkgtoken.ClientToken); ok {
			return ct
		}
	}
	return nil
}
