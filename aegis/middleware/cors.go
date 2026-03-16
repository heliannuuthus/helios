package middleware

import (
	"bytes"
	"io"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-json-experiment/json"

	"github.com/heliannuuthus/helios/aegis/config"
	"github.com/heliannuuthus/helios/aegis/internal/cache"
	"github.com/heliannuuthus/helios/pkg/logger"
)

const (
	wildcard             = "*"
	defaultAllowMethods  = "GET, POST, PUT, DELETE, OPTIONS, PATCH"
	defaultAllowHeaders  = "Content-Type, Authorization, X-Requested-With"
	defaultExposeHeaders = "Location"
	defaultMaxAge        = "86400"

	headerOrigin           = "Origin"
	headerAllowOrigin      = "Access-Control-Allow-Origin"
	headerAllowMethods     = "Access-Control-Allow-Methods"
	headerAllowHeaders     = "Access-Control-Allow-Headers"
	headerExposeHeaders    = "Access-Control-Expose-Headers"
	headerAllowCredentials = "Access-Control-Allow-Credentials"
	headerMaxAge           = "Access-Control-Max-Age"
)

// CORS 创建 CORS 中间件
// 优先检查配置文件的 origins（pallas 无条件放行），然后检查应用的 allowed_origins
func CORS(cacheManager *cache.Manager) gin.HandlerFunc {
	origins := config.GetCORSOrigins()

	return func(c *gin.Context) {
		origin := c.GetHeader(headerOrigin)

		c.Header(headerAllowMethods, defaultAllowMethods)
		c.Header(headerAllowHeaders, defaultAllowHeaders)
		c.Header(headerExposeHeaders, defaultExposeHeaders)
		c.Header(headerAllowCredentials, "true")
		c.Header(headerMaxAge, defaultMaxAge)
		c.Header("Vary", "Origin")

		if c.Request.Method == "OPTIONS" {
			if origin != "" {
				c.Header(headerAllowOrigin, origin)
			}
			c.AbortWithStatus(204)
			return
		}

		setAllowOrigin(c, origins, cacheManager, origin)
		c.Next()
	}
}

// setAllowOrigin 设置允许的 Origin（配置文件 + 应用配置）
func setAllowOrigin(c *gin.Context, origins []string, cacheManager *cache.Manager, origin string) {
	if origin == "" {
		return
	}

	if isOriginAllowed(origin, origins) {
		c.Header(headerAllowOrigin, origin)
		return
	}

	clientID := getClientID(c, "client_id")
	if clientID != "" && cacheManager != nil {
		if validateAppOrigin(c, cacheManager, clientID, origin) {
			c.Header(headerAllowOrigin, origin)
		}
	}
}

// validateAppOrigin 验证请求来源是否在应用的允许列表中
func validateAppOrigin(c *gin.Context, cm *cache.Manager, clientID, origin string) bool {
	app, err := cm.GetApplication(c.Request.Context(), clientID)
	if err != nil {
		return false
	}

	allowedOrigins := app.GetAllowedOrigins()
	if len(allowedOrigins) == 0 {
		return true
	}

	return isOriginAllowed(origin, allowedOrigins)
}

// getClientID 从请求中获取 client_id（query -> form -> JSON body）
// JSON body 使用 peek 方式读取后还原，不影响下游 handler
func getClientID(c *gin.Context, paramName string) string {
	if clientID := c.Query(paramName); clientID != "" {
		return clientID
	}

	if clientID := c.PostForm(paramName); clientID != "" {
		return clientID
	}

	if c.Request.Body != nil && c.ContentType() == "application/json" {
		bodyBytes, err := io.ReadAll(c.Request.Body)
		if err := c.Request.Body.Close(); err != nil {
			logger.Warnf("failed to close request body: %v", err)
		}
		c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		if err == nil && len(bodyBytes) > 0 {
			var body map[string]any
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
	normalized := strings.TrimRight(origin, "/")
	for _, o := range origins {
		if o == wildcard || strings.TrimRight(o, "/") == normalized {
			return true
		}
	}
	return false
}
