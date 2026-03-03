package web

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/heliannuuthus/helios/pkg/logger"
)

// Guard 路由级声明式鉴权器。
// 在 Intercept 阶段（RequireAuth）已完成认证并注入 TokenContext 后，
// Guard 在 Check 阶段读取 TokenContext 并依次执行 Requirement 条件。
type Guard struct {
	checker *RelationChecker
}

// NewGuard 创建 Guard 实例。
func NewGuard(checker *RelationChecker) *Guard {
	return &Guard{checker: checker}
}

// Require 返回 Gin HandlerFunc，依次执行所有 Requirement。
// TokenContext 缺失 → 401；任一条件不满足 → 403。
func (g *Guard) Require(requirements ...Requirement) gin.HandlerFunc {
	return func(c *gin.Context) {
		tc := TokenContextFromGin(c)
		if tc == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":   "unauthorized",
				"message": "未登录或登录已过期",
			})
			return
		}

		for _, req := range requirements {
			if err := req.Enforce(c.Request.Context(), tc, g.checker); err != nil {
				if errors.Is(err, errForbidden) {
					c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
						"error":   "forbidden",
						"message": "无权限访问",
					})
				} else {
					logger.Errorf("[Guard] requirement check failed: %v", err)
					c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
						"error":   "internal_error",
						"message": "鉴权失败",
					})
				}
				return
			}
		}

		c.Next()
	}
}

// RequireHTTP 返回 net/http 中间件，依次执行所有 Requirement。
func (g *Guard) RequireHTTP(requirements ...Requirement) MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tc, ok := r.Context().Value(ClaimsKey).(*TokenContext)
			if !ok || tc == nil {
				writeJSONError(w, http.StatusUnauthorized, "unauthorized", "未登录或登录已过期")
				return
			}

			for _, req := range requirements {
				if err := req.Enforce(r.Context(), tc, g.checker); err != nil {
					if errors.Is(err, errForbidden) {
						writeJSONError(w, http.StatusForbidden, "forbidden", "无权限访问")
					} else {
						logger.Errorf("[Guard] requirement check failed: %v", err)
						writeJSONError(w, http.StatusInternalServerError, "internal_error", "鉴权失败")
					}
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// Guard 从 GinMiddleware 创建与之共享 RelationChecker 的 Guard 实例。
func (m *GinMiddleware) Guard() *Guard {
	return NewGuard(m.checker)
}

// Guard 从 Middleware 创建与之共享 RelationChecker 的 Guard 实例。
func (m *Middleware) Guard() *Guard {
	return NewGuard(m.checker)
}
