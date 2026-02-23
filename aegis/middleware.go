package aegis

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/heliannuuthus/helios/aegis/internal/token"
	pkgtoken "github.com/heliannuuthus/helios/pkg/aegis/token"
)

// Middleware 认证中间件（用于验证 CAT）
type Middleware struct {
	tokenSvc *token.Service
}

// NewMiddleware 创建中间件
func NewMiddleware(tokenSvc *token.Service) *Middleware {
	return &Middleware{
		tokenSvc: tokenSvc,
	}
}

// RequireClientAuth 要求客户端认证（验证 CAT）
func (m *Middleware) RequireClientAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenStr := m.extractToken(c)
		if tokenStr == "" {
			c.Header("WWW-Authenticate", pkgtoken.TokenTypeBearer)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":             "invalid_token",
				"error_description": "missing client access token",
			})
			return
		}

		// 验证 CAT
		t, err := m.tokenSvc.Verify(c.Request.Context(), tokenStr)
		if err != nil {
			c.Header("WWW-Authenticate", pkgtoken.TokenTypeBearer+` error="invalid_token"`)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":             "invalid_token",
				"error_description": err.Error(),
			})
			return
		}
		claims, ok := t.(*pkgtoken.ClientAccessToken)
		if !ok {
			c.Header("WWW-Authenticate", pkgtoken.TokenTypeBearer+` error="invalid_token"`)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":             "invalid_token",
				"error_description": "expected CAT token",
			})
			return
		}

		c.Set("client_claims", claims)
		c.Next()
	}
}

func (*Middleware) extractToken(c *gin.Context) string {
	// 从 Authorization header
	auth := c.GetHeader(HeaderAuthorization)
	if strings.HasPrefix(auth, BearerPrefix) {
		return auth[7:]
	}
	return ""
}

// GetClientClaims 从上下文获取客户端信息
func GetClientClaims(c *gin.Context) *pkgtoken.ClientAccessToken {
	if claims, exists := c.Get("client_claims"); exists {
		if cat, ok := claims.(*pkgtoken.ClientAccessToken); ok {
			return cat
		}
	}
	return nil
}
