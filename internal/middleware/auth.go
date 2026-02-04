package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"aidanwoods.dev/go-paseto"
	"github.com/gin-gonic/gin"

	"github.com/heliannuuthus/helios/internal/config"
	"github.com/heliannuuthus/helios/pkg/aegis/token"
	"github.com/heliannuuthus/helios/pkg/logger"
)

// AuthMiddleware 认证中间件（可选认证）
// Deprecated: 使用 OptionalToken 替代
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Warnf("[Auth] AuthMiddleware is deprecated, use OptionalToken instead")
		c.Next()
	}
}

// RequireAuth 要求认证中间件
// Deprecated: 使用 RequireToken 替代
func RequireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Warnf("[Auth] RequireAuth is deprecated, use RequireToken instead")
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"detail": "deprecated middleware"})
	}
}

// tokenPreview 生成 token 预览（避免在日志中暴露完整 token）
func tokenPreview(tokenStr string, length int) string {
	if len(tokenStr) <= length {
		return tokenStr
	}
	return tokenStr[:length]
}

// RequireToken 新版本认证中间件（使用 token.Interpreter）
func RequireToken(v *token.Interpreter) gin.HandlerFunc {
	return func(c *gin.Context) {
		authorization := c.GetHeader("Authorization")
		if authorization == "" {
			logger.Debugf("[Auth] 请求未携带 Authorization 头 - Path: %s, IP: %s", c.Request.URL.Path, c.ClientIP())
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"detail": "未登录或登录已过期"})
			return
		}

		tokenStr := authorization
		if strings.HasPrefix(authorization, "Bearer ") {
			tokenStr = authorization[7:]
		}

		identity, err := v.Interpret(c.Request.Context(), tokenStr)
		if err != nil {
			logger.Warnf("[Auth] Token 验证失败 - Path: %s, IP: %s, Error: %v, TokenPreview: %s...",
				c.Request.URL.Path,
				c.ClientIP(),
				err,
				tokenPreview(tokenStr, 20))
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"detail": "未登录或登录已过期"})
			return
		}

		openID := ""
		if identity.User != nil {
			openID = identity.User.Subject
		}
		logger.Infof("[Auth] 认证成功 - Path: %s, OpenID: %s", c.Request.URL.Path, openID)
		c.Set("user", identity)
		c.Next()
	}
}

// OptionalToken 新版本可选认证中间件（使用 token.Interpreter）
func OptionalToken(v *token.Interpreter) gin.HandlerFunc {
	return func(c *gin.Context) {
		authorization := c.GetHeader("Authorization")
		if authorization == "" {
			c.Next()
			return
		}

		tokenStr := authorization
		if strings.HasPrefix(authorization, "Bearer ") {
			tokenStr = authorization[7:]
		}

		identity, err := v.Interpret(c.Request.Context(), tokenStr)
		if err == nil && identity != nil {
			openID := ""
			if identity.User != nil {
				openID = identity.User.Subject
			}
			logger.Infof("[Auth] 可选认证成功 - Path: %s, OpenID: %s", c.Request.URL.Path, openID)
			c.Set("user", identity)
		}

		c.Next()
	}
}

// HermesSymmetricKeyProvider 基于 Hermes 配置的对称密钥提供者
// 从 hermes 配置的 aegis.secret-key 读取密钥
type HermesSymmetricKeyProvider struct {
	key paseto.V4SymmetricKey // 缓存解析后的 key
}

// NewHermesSymmetricKeyProvider 创建基于 Hermes 配置的对称密钥提供者
func NewHermesSymmetricKeyProvider() (*HermesSymmetricKeyProvider, error) {
	secretBytes, err := config.GetHermesAegisSecretKeyBytes()
	if err != nil {
		return nil, fmt.Errorf("get hermes aegis secret key: %w", err)
	}

	// 解析对称密钥（32 字节）
	symmetricKey, err := token.ParseSymmetricKeyFromBytes(secretBytes)
	if err != nil {
		return nil, fmt.Errorf("parse hermes aegis symmetric key: %w", err)
	}

	return &HermesSymmetricKeyProvider{key: symmetricKey}, nil
}

// Get 获取解密密钥（忽略 audience 参数，使用 hermes 配置的密钥）
func (p *HermesSymmetricKeyProvider) Get(ctx context.Context, audience string) (paseto.V4SymmetricKey, error) {
	return p.key, nil
}

// HermesPublicKeyProvider 基于 HTTP 端点的公钥提供者
// 从 Aegis 服务获取公钥
type HermesPublicKeyProvider struct {
	endpoint string
	cache    map[string]paseto.V4AsymmetricPublicKey
}

// NewHermesPublicKeyProvider 创建基于 HTTP 端点的公钥提供者
func NewHermesPublicKeyProvider(endpoint string) *HermesPublicKeyProvider {
	return &HermesPublicKeyProvider{
		endpoint: endpoint,
		cache:    make(map[string]paseto.V4AsymmetricPublicKey),
	}
}

// Get 获取公钥（从远程服务获取）
func (p *HermesPublicKeyProvider) Get(ctx context.Context, clientID string) (paseto.V4AsymmetricPublicKey, error) {
	// TODO: 实现从 Aegis 服务获取公钥
	// 现在先使用本地配置的公钥（从域签名密钥派生）
	secretKeyBytes, err := config.GetHermesAegisSecretKeyBytes()
	if err != nil {
		return paseto.V4AsymmetricPublicKey{}, fmt.Errorf("get secret key: %w", err)
	}

	secretKey, err := token.ParseSecretKeyFromJWK(secretKeyBytes)
	if err != nil {
		return paseto.V4AsymmetricPublicKey{}, fmt.Errorf("parse secret key: %w", err)
	}

	return secretKey.Public(), nil
}

// HermesSecretKeyProvider 基于 Hermes 配置的私钥提供者
// 从 hermes 配置读取 Ed25519 私钥（用于签发 CAT）
type HermesSecretKeyProvider struct {
	key paseto.V4AsymmetricSecretKey // 缓存解析后的 key
}

// NewHermesSecretKeyProvider 创建基于 Hermes 配置的私钥提供者
func NewHermesSecretKeyProvider() (*HermesSecretKeyProvider, error) {
	secretBytes, err := config.GetHermesAegisSecretKeyBytes()
	if err != nil {
		return nil, fmt.Errorf("get hermes aegis secret key: %w", err)
	}

	// 解析 Ed25519 私钥
	secretKey, err := token.ParseSecretKeyFromJWK(secretBytes)
	if err != nil {
		return nil, fmt.Errorf("parse hermes aegis secret key: %w", err)
	}

	return &HermesSecretKeyProvider{key: secretKey}, nil
}

// Get 获取私钥（忽略 keyID 参数，使用 hermes 配置的密钥）
func (p *HermesSecretKeyProvider) Get(ctx context.Context, keyID string) (paseto.V4AsymmetricSecretKey, error) {
	return p.key, nil
}
