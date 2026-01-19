package auth

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// Middleware 认证中间件
type Middleware struct {
	tokenManager *TokenManager
}

// NewMiddleware 创建中间件
func NewMiddleware(tokenManager *TokenManager) *Middleware {
	return &Middleware{tokenManager: tokenManager}
}

// RequireAuth 要求认证
func (m *Middleware) RequireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := m.extractToken(c)
		if token == "" {
			c.Header("WWW-Authenticate", "Bearer")
			c.AbortWithStatusJSON(http.StatusUnauthorized, Error{
				Code:        ErrInvalidToken,
				Description: "missing access token",
			})
			return
		}

		// 尝试验证为 Access Token
		identity, err := m.tokenManager.VerifyAccessToken(token)
		if err != nil {
			// 尝试验证为 ID Token
			identity, err = m.tokenManager.VerifyIDToken(token)
			if err != nil {
				c.Header("WWW-Authenticate", "Bearer error=\"invalid_token\"")
				c.AbortWithStatusJSON(http.StatusUnauthorized, Error{
					Code:        ErrInvalidToken,
					Description: err.Error(),
				})
				return
			}
		}

		c.Set("identity", identity)
		c.Next()
	}
}

// OptionalAuth 可选认证
func (m *Middleware) OptionalAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := m.extractToken(c)
		if token == "" {
			c.Next()
			return
		}

		// 尝试验证
		identity, err := m.tokenManager.VerifyAccessToken(token)
		if err != nil {
			identity, err = m.tokenManager.VerifyIDToken(token)
		}
		if err == nil && identity != nil {
			c.Set("identity", identity)
		}

		c.Next()
	}
}

// RequireDomain 要求特定域
func (m *Middleware) RequireDomain(domain Domain) gin.HandlerFunc {
	return func(c *gin.Context) {
		identity := GetIdentity(c)
		if identity == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, Error{
				Code:        ErrInvalidToken,
				Description: "authentication required",
			})
			return
		}

		if identity.Domain != domain {
			c.AbortWithStatusJSON(http.StatusForbidden, Error{
				Code:        ErrAccessDenied,
				Description: "access denied for this domain",
			})
			return
		}

		c.Next()
	}
}

func (m *Middleware) extractToken(c *gin.Context) string {
	// 从 Authorization header
	auth := c.GetHeader("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return auth[7:]
	}
	return ""
}

// GetIdentity 从上下文获取用户身份
func GetIdentity(c *gin.Context) *Identity {
	if identity, exists := c.Get("identity"); exists {
		return identity.(*Identity)
	}
	return nil
}

// GetUserID 从上下文获取用户 ID
func GetUserID(c *gin.Context) string {
	if identity := GetIdentity(c); identity != nil {
		return identity.UserID
	}
	return ""
}

// GetDomain 从上下文获取域
func GetDomain(c *gin.Context) Domain {
	if identity := GetIdentity(c); identity != nil {
		return identity.Domain
	}
	return ""
}
