package middleware

import (
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/heliannuuthus/helios/internal/config"
)

const (
	wildcard               = "*"
	defaultAllowMethods    = "GET, POST, PUT, DELETE, OPTIONS, PATCH"
	defaultAllowHeaders    = "Content-Type, Authorization, X-Requested-With"
	defaultMaxAge          = "86400"
	headerOrigin           = "Origin"
	headerAllowOrigin      = "Access-Control-Allow-Origin"
	headerAllowMethods     = "Access-Control-Allow-Methods"
	headerAllowHeaders     = "Access-Control-Allow-Headers"
	headerAllowCredentials = "Access-Control-Allow-Credentials"
	headerMaxAge           = "Access-Control-Max-Age"
)

// CORS 中间件
func CORS() gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg := config.Zwei()
		origin := c.GetHeader(headerOrigin)

		// 设置 CORS 头
		setAllowOrigin(c, cfg, origin)
		setAllowMethods(c, cfg)
		setAllowHeaders(c, cfg)
		setCredentials(c, cfg)
		c.Header(headerMaxAge, defaultMaxAge)

		// 处理预检请求
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

// setAllowOrigin 设置允许的 Origin
func setAllowOrigin(c *gin.Context, cfg *config.Cfg, origin string) {
	if origin == "" {
		return
	}

	origins := cfg.GetStringSlice("cors.origins")
	if isOriginAllowed(origin, origins) {
		c.Header(headerAllowOrigin, origin)
	}
}

// isOriginAllowed 检查 origin 是否在允许列表中
func isOriginAllowed(origin string, origins []string) bool {
	for _, o := range origins {
		if o == wildcard || o == origin {
			return true
		}
	}
	return false
}

// setAllowMethods 设置允许的方法
func setAllowMethods(c *gin.Context, cfg *config.Cfg) {
	methods := defaultAllowMethods
	allowMethods := cfg.GetStringSlice("cors.allow_methods")
	if len(allowMethods) > 0 && allowMethods[0] != wildcard {
		methods = strings.Join(allowMethods, ", ")
	}
	c.Header(headerAllowMethods, methods)
}

// setAllowHeaders 设置允许的请求头
func setAllowHeaders(c *gin.Context, cfg *config.Cfg) {
	headers := defaultAllowHeaders
	allowHeaders := cfg.GetStringSlice("cors.allow_headers")
	if len(allowHeaders) > 0 && allowHeaders[0] != wildcard {
		headers = strings.Join(allowHeaders, ", ")
	}
	c.Header(headerAllowHeaders, headers)
}

// setCredentials 设置是否允许携带凭证
func setCredentials(c *gin.Context, cfg *config.Cfg) {
	if cfg.GetBool("cors.allow_credentials") {
		c.Header(headerAllowCredentials, "true")
	}
}
