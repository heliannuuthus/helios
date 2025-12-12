package middleware

import (
	"choosy-backend/internal/config"

	"github.com/gin-gonic/gin"
)

// CORS 中间件
func CORS() gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		origins := config.GetStringSlice("cors.origins")

		// 检查 origin 是否在允许列表中
		allowed := false
		for _, o := range origins {
			if o == "*" || o == origin {
				allowed = true
				break
			}
		}

		if allowed {
			c.Header("Access-Control-Allow-Origin", origin)
		} else if len(origins) > 0 && origins[0] == "*" {
			c.Header("Access-Control-Allow-Origin", "*")
		}

		// 允许的方法
		methods := "GET, POST, PUT, DELETE, OPTIONS, PATCH"
		allowMethods := config.GetStringSlice("cors.allow_methods")
		if len(allowMethods) > 0 && allowMethods[0] != "*" {
			methods = ""
			for i, m := range allowMethods {
				if i > 0 {
					methods += ", "
				}
				methods += m
			}
		}
		c.Header("Access-Control-Allow-Methods", methods)

		// 允许的头
		headers := "Content-Type, Authorization, X-Requested-With"
		allowHeaders := config.GetStringSlice("cors.allow_headers")
		if len(allowHeaders) > 0 && allowHeaders[0] != "*" {
			headers = ""
			for i, h := range allowHeaders {
				if i > 0 {
					headers += ", "
				}
				headers += h
			}
		}
		c.Header("Access-Control-Allow-Headers", headers)

		// 允许携带凭证
		if config.GetBool("cors.allow_credentials") {
			c.Header("Access-Control-Allow-Credentials", "true")
		}

		// 预检请求缓存时间
		c.Header("Access-Control-Max-Age", "86400")

		// 处理预检请求
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}
