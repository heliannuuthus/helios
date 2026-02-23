package middleware

import (
	"bytes"
	"github.com/go-json-experiment/json"
	"io"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/heliannuuthus/helios/aegis/internal/cache"
	"github.com/heliannuuthus/helios/pkg/config"
)

const (
	wildcard               = "*"
	defaultAllowMethods    = "GET, POST, PUT, DELETE, OPTIONS, PATCH"
	defaultAllowHeaders    = "Content-Type, Authorization, X-Requested-With"
	defaultExposeHeaders   = "Location"
	defaultMaxAge          = "86400"
	headerOrigin           = "Origin"
	headerAllowOrigin      = "Access-Control-Allow-Origin"
	headerAllowMethods     = "Access-Control-Allow-Methods"
	headerAllowHeaders     = "Access-Control-Allow-Headers"
	headerExposeHeaders    = "Access-Control-Expose-Headers"
	headerAllowCredentials = "Access-Control-Allow-Credentials"
	headerMaxAge           = "Access-Control-Max-Age"
)

// CORSWithConfig 创建 CORS 中间件
// 优先检查配置文件的 origins（aegis-ui 无条件放行），然后检查应用的 allowed_origins
func CORSWithConfig(cfg *config.Cfg, cacheManager *cache.Manager) gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.GetHeader(headerOrigin)

		// 设置 CORS 头（优先配置文件，其次应用配置）
		setAllowOrigin(c, cfg, cacheManager, origin)
		setAllowMethods(c, cfg)
		setAllowHeaders(c, cfg)
		setExposeHeaders(c)
		setCredentials(c, cfg)
		c.Header(headerMaxAge, defaultMaxAge)
		// Vary: Origin 防止 CDN/代理缓存错误的 CORS 头
		c.Header("Vary", "Origin")

		// 处理预检请求
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

// setAllowOrigin 设置允许的 Origin（配置文件 + 应用配置）
func setAllowOrigin(c *gin.Context, cfg *config.Cfg, cacheManager *cache.Manager, origin string) {
	if origin == "" {
		return
	}

	// 1. 先检查配置文件的 origins（aegis-ui 无条件放行）
	origins := cfg.GetStringSlice("cors.origins")
	if isOriginAllowed(origin, origins) {
		c.Header(headerAllowOrigin, origin)
		return
	}

	// 2. 如果带 client_id，检查应用的 allowed_origins
	clientID := getClientID(c, "client_id")
	if clientID != "" && cacheManager != nil {
		allowed, err := cacheManager.ValidateAppOrigin(c.Request.Context(), clientID, origin)
		if err == nil && allowed {
			c.Header(headerAllowOrigin, origin)
		}
	}
}

// getClientID 从请求中获取 client_id（query -> form -> JSON body）
// JSON body 使用 peek 方式读取后还原，不影响下游 handler
func getClientID(c *gin.Context, paramName string) string {
	// 1. 从 query 参数获取
	if clientID := c.Query(paramName); clientID != "" {
		return clientID
	}

	// 2. 从 form 参数获取
	if clientID := c.PostForm(paramName); clientID != "" {
		return clientID
	}

	// 3. 从 JSON body peek（读取后还原 body）
	if c.Request.Body != nil && c.ContentType() == "application/json" {
		bodyBytes, err := io.ReadAll(c.Request.Body)
		_ = c.Request.Body.Close()
		// 无论是否解析成功，都还原 body
		c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		if err == nil && len(bodyBytes) > 0 {
			var body map[string]interface{}
			if json.Unmarshal(bodyBytes, &body) == nil {
				if clientID, ok := body[paramName].(string); ok && clientID != "" {
					return clientID
				}
			}
		}
	}

	return ""
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

// setExposeHeaders 设置允许前端 AJAX 读取的响应头（300 重定向需要读取 Location）
func setExposeHeaders(c *gin.Context) {
	c.Header(headerExposeHeaders, defaultExposeHeaders)
}

// setCredentials 设置是否允许携带凭证
func setCredentials(c *gin.Context, cfg *config.Cfg) {
	if cfg.GetBool("cors.allow_credentials") {
		c.Header(headerAllowCredentials, "true")
	}
}
