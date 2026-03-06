package guard

import (
	stderrors "errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/heliannuuthus/helios/pkg/aegis/utils/errors"
	"github.com/heliannuuthus/helios/pkg/aegis/utils/relation"
	"github.com/heliannuuthus/helios/pkg/aegis/web"
	"github.com/heliannuuthus/helios/pkg/logger"
)

// GinGuard Gin 框架适配器。
type GinGuard struct {
	audience string
}

// NewGinGuard 创建 Gin Guard。
func NewGinGuard(audience string) *GinGuard {
	return &GinGuard{audience: audience}
}

// Require 返回 Gin 中间件：认证 + 依次执行所有 Requirement。
// 无 requirements 时等价于纯认证。
func (g *GinGuard) Require(requirements ...web.Requirement) gin.HandlerFunc {
	return func(c *gin.Context) {
		tc, err := web.Authenticate(c.Request)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":   "unauthorized",
				"message": "未登录或登录已过期",
			})
			return
		}

		ctx := web.WithRelationResolver(c.Request.Context(), extractResolver(c))
		ctx = web.WithTokenContext(ctx, tc)
		c.Request = c.Request.WithContext(ctx)

		for _, req := range requirements {
			if err := req.Enforce(ctx); err != nil {
				switch {
				case stderrors.Is(err, errors.ErrUnauthorized):
					c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
						"error":   "unauthorized",
						"message": "未登录或登录已过期",
					})
				case stderrors.Is(err, errors.ErrForbidden):
					c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
						"error":   "forbidden",
						"message": "无权限访问",
					})
				default:
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

func extractResolver(c *gin.Context) *relation.Resolver {
	data := make(map[string]any, 3)

	if ginParams := c.Params; len(ginParams) > 0 {
		pathMap := make(map[string]any, len(ginParams))
		for _, kv := range ginParams {
			pathMap[kv.Key] = kv.Value
		}
		data["path"] = pathMap
	}

	if q := c.Request.URL.Query(); len(q) > 0 {
		queryMap := make(map[string]any, len(q))
		for k, v := range q {
			if len(v) > 0 {
				queryMap[k] = v[0]
			}
		}
		data["query"] = queryMap
	}

	if bodyMap := web.ParseBody(c.Request); bodyMap != nil {
		data["body"] = bodyMap
	}

	return relation.NewResolver(data)
}
