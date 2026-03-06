package guard

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-json-experiment/json"

	"github.com/heliannuuthus/helios/pkg/aegis/web"
	"github.com/heliannuuthus/helios/pkg/logger"
)

// GinGuard Gin 框架适配器，将 Middleware 的纯逻辑映射为 gin.HandlerFunc。
type GinGuard struct {
	mw *web.Middleware
}

// NewGinGuard 创建 Gin Guard。
func NewGinGuard(mw *web.Middleware) *GinGuard {
	return &GinGuard{mw: mw}
}

// Require 返回 Gin 中间件：认证 + 依次执行所有 Requirement。
// 无 requirements 时等价于纯认证。
func (g *GinGuard) Require(requirements ...web.Requirement) gin.HandlerFunc {
	return func(c *gin.Context) {
		tc, err := g.mw.Authenticate(c.Request)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":   "unauthorized",
				"message": "未登录或登录已过期",
			})
			return
		}

		ctx := context.WithValue(c.Request.Context(), web.ClaimsKey, tc)
		ctx = web.SetParams(ctx, extractParams(c))
		c.Request = c.Request.WithContext(ctx)

		for _, req := range requirements {
			if err := req.Enforce(ctx); err != nil {
				switch {
				case errors.Is(err, web.ErrUnauthorized):
					c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
						"error":   "unauthorized",
						"message": "未登录或登录已过期",
					})
				case errors.Is(err, web.ErrForbidden):
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

// extractParams 从 Gin context 一次性提取 path / query / body 参数，构建 Params。
func extractParams(c *gin.Context) *web.Params {
	var pathMap map[string]any
	if params := c.Params; len(params) > 0 {
		pathMap = make(map[string]any, len(params))
		for _, p := range params {
			pathMap[p.Key] = p.Value
		}
	}

	var queryMap map[string]any
	if q := c.Request.URL.Query(); len(q) > 0 {
		queryMap = make(map[string]any, len(q))
		for k, v := range q {
			if len(v) > 0 {
				queryMap[k] = v[0]
			}
		}
	}

	bodyMap := parseBody(c.Request)

	return web.NewParams(pathMap, queryMap, bodyMap)
}

func parseBody(r *http.Request) map[string]any {
	if r.Body == nil {
		return nil
	}

	ct := r.Header.Get("Content-Type")
	switch {
	case strings.HasPrefix(ct, "application/json"):
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return nil
		}
		r.Body = io.NopCloser(strings.NewReader(string(body)))
		var m map[string]any
		if err := json.Unmarshal(body, &m); err != nil {
			return nil
		}
		return m

	case strings.HasPrefix(ct, "application/x-www-form-urlencoded"),
		strings.HasPrefix(ct, "multipart/form-data"):
		if err := r.ParseForm(); err != nil {
			return nil
		}
		m := make(map[string]any, len(r.PostForm))
		for k, v := range r.PostForm {
			if len(v) > 0 {
				m[k] = v[0]
			}
		}
		return m
	}

	return nil
}
