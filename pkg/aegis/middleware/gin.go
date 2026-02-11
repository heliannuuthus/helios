package middleware

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/heliannuuthus/helios/pkg/aegis/keys"
	"github.com/heliannuuthus/helios/pkg/aegis/token"
)

// GinFactory Gin 框架中间件工厂
type GinFactory struct {
	*Factory
}

// NewGinFactory 创建 Gin 中间件工厂
// endpoint: Aegis 服务端点（如 http://auth.example.com）
// publicKeyProvider: 公钥提供者（用于验证 UAT 签名）
// symmetricKeyProvider: 对称密钥提供者（用于解密 footer）
// secretKeyProvider: 私钥提供者（用于签发 CAT）
func NewGinFactory(
	endpoint string,
	publicKeyProvider keys.PublicKeyProvider,
	symmetricKeyProvider keys.SymmetricKeyProvider,
	secretKeyProvider keys.SecretKeyProvider,
) *GinFactory {
	factory := NewFactory(endpoint, publicKeyProvider, symmetricKeyProvider, secretKeyProvider)
	return &GinFactory{
		Factory: factory,
	}
}

// WithAudience 为特定 audience 创建 Gin 中间件
func (f *GinFactory) WithAudience(audience string) *GinMiddleware {
	return &GinMiddleware{
		Middleware: f.Factory.WithAudience(audience),
	}
}

// GinMiddleware Gin 框架中间件适配器
type GinMiddleware struct {
	*Middleware
}

// RequireAuth 返回要求认证的 Gin 中间件
func (m *GinMiddleware) RequireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, err := m.authenticate(c.Request)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":   "unauthorized",
				"message": "未登录或登录已过期",
			})
			return
		}

		c.Set(string(ClaimsKey), claims)
		c.Next()
	}
}

// RequireRelation 返回要求指定关系的 Gin 中间件
func (m *GinMiddleware) RequireRelation(relation string) gin.HandlerFunc {
	return m.RequireRelationOn(relation, "*", "*")
}

// RequireRelationOn 返回要求指定关系的 Gin 中间件（指定资源）
func (m *GinMiddleware) RequireRelationOn(relation, objectType, objectID string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 1. 认证
		claims, err := m.authenticate(c.Request)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":   "unauthorized",
				"message": "未登录或登录已过期",
			})
			return
		}

		// 2. 鉴权
		if err := m.authorize(c.Request.Context(), claims, relation, objectType, objectID); err != nil {
			if errors.Is(err, errForbidden) {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
					"error":   "forbidden",
					"message": "无权限访问",
				})
			} else {
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
					"error":   "internal_error",
					"message": "鉴权失败",
				})
			}
			return
		}

		c.Set(string(ClaimsKey), claims)
		c.Next()
	}
}

// RequireAnyRelation 返回要求任意一个指定关系的 Gin 中间件
func (m *GinMiddleware) RequireAnyRelation(relations ...string) gin.HandlerFunc {
	return m.RequireAnyRelationOn(relations, "*", "*")
}

// RequireAnyRelationOn 返回要求任意一个指定关系的 Gin 中间件（指定资源）
func (m *GinMiddleware) RequireAnyRelationOn(relations []string, objectType, objectID string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 1. 认证
		claims, err := m.authenticate(c.Request)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":   "unauthorized",
				"message": "未登录或登录已过期",
			})
			return
		}

		// 2. 鉴权
		if err := m.authorizeAny(c.Request.Context(), claims, relations, objectType, objectID); err != nil {
			if errors.Is(err, errForbidden) {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
					"error":   "forbidden",
					"message": "无权限访问",
				})
			} else {
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
					"error":   "internal_error",
					"message": "鉴权失败",
				})
			}
			return
		}

		c.Set(string(ClaimsKey), claims)
		c.Next()
	}
}

// GetTokenFromGin 从 Gin context 中获取验证后的 Token
func GetTokenFromGin(c *gin.Context) token.Token {
	t, exists := c.Get(string(ClaimsKey))
	if !exists {
		return nil
	}
	result, ok := t.(token.Token)
	if !ok {
		return nil
	}
	return result
}

// GetOpenIDFromGin 从 Gin context 中获取用户标识（t_user.openid）
func GetOpenIDFromGin(c *gin.Context) string {
	t := GetTokenFromGin(c)
	if t == nil {
		return ""
	}
	if uat, ok := token.AsUAT(t); ok && uat.HasUser() {
		return uat.GetOpenID()
	}
	return ""
}
