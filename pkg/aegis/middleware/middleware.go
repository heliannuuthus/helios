// Package middleware 提供 Aegis 认证和鉴权中间件
//
// 使用示例：
//
//	// 创建全局 Factory
//	factory, err := middleware.NewFactory(ctx, "http://auth.example.com", secretKeyProvider)
//
//	// 为特定 audience 创建中间件
//	mw := factory.WithAudience("my-service-id")
//
//	r.Use(mw.RequireAuth())                      // 仅认证
//	r.GET("/admin", mw.RequireRelation("admin")) // 认证 + 鉴权
package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/lestrrat-go/jwx/v3/jwa"

	"github.com/heliannuuthus/helios/pkg/aegis/token"
)

// ContextKey 上下文 key 类型
type ContextKey string

const (
	// ClaimsKey 用户身份信息在 context 中的 key
	ClaimsKey ContextKey = "aegis:claims"
)

// Factory 中间件工厂
// 用于创建绑定特定 audience 的中间件
type Factory struct {
	signKeyProvider    token.KeyProvider // 验证 UAT 签名（公钥，来自 JWKS）
	encryptKeyProvider token.KeyProvider // 解密 UAT subject（对称密钥，dir 模式）
	catSignKeyProvider token.KeyProvider // 签发 CAT（对称密钥，HS256）
	checker            *token.Checker
}

// NewFactory 创建中间件工厂
// ctx: 用于初始化 JWKS 缓存
// endpoint: Aegis 服务端点（如 http://auth.example.com）
// secretKeyProvider: 服务密钥提供者（用于解密 token 和签发 CAT）
//
// secretKeyProvider 提供的密钥会被自动转换：
//   - 解密 UAT: 使用 dir 算法
//   - 签发 CAT: 使用 HS256 算法
func NewFactory(ctx context.Context, endpoint string, secretKeyProvider token.KeyProvider) (*Factory, error) {
	// 自动创建签名公钥提供者（通过 JWKS 接口获取）
	signKeyProvider, err := token.NewJWKSKeyProvider(ctx, func() string { return endpoint })
	if err != nil {
		return nil, err
	}

	// 包装密钥提供者，设置正确的算法
	encryptKeyProvider := token.NewEncryptKeyProvider(secretKeyProvider, jwa.DIRECT())
	catSignKeyProvider := token.NewSignKeyProvider(secretKeyProvider, jwa.HS256())

	return &Factory{
		signKeyProvider:    signKeyProvider,
		encryptKeyProvider: encryptKeyProvider,
		catSignKeyProvider: catSignKeyProvider,
		checker:            token.NewChecker(endpoint, catSignKeyProvider),
	}, nil
}

// WithAudience 为特定 audience 创建中间件
// audience: 服务 ID（用于 token 验证）
func (f *Factory) WithAudience(audience string) *Middleware {
	interpreter := token.NewInterpreter(f.signKeyProvider, f.encryptKeyProvider)
	return &Middleware{
		interpreter: interpreter,
		checker:     f.checker,
	}
}

// Middleware Aegis 中间件
type Middleware struct {
	interpreter *token.Interpreter
	checker     *token.Checker
}

// MiddlewareFunc 中间件函数类型
type MiddlewareFunc func(next http.Handler) http.Handler

// RequireAuth 返回要求认证的中间件
// 只验证 token，不检查关系
func (m *Middleware) RequireAuth() MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, err := m.authenticate(r)
			if err != nil {
				http.Error(w, `{"error":"unauthorized","message":"未登录或登录已过期"}`, http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), ClaimsKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireRelation 返回要求指定关系的中间件
func (m *Middleware) RequireRelation(relation string) MiddlewareFunc {
	return m.RequireRelationOn(relation, "*", "*")
}

// RequireRelationOn 返回要求指定关系的中间件（指定资源）
func (m *Middleware) RequireRelationOn(relation, objectType, objectID string) MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 1. 认证
			claims, err := m.authenticate(r)
			if err != nil {
				http.Error(w, `{"error":"unauthorized","message":"未登录或登录已过期"}`, http.StatusUnauthorized)
				return
			}

			// 2. 鉴权
			if err := m.authorize(r.Context(), claims, relation, objectType, objectID); err != nil {
				if err == errForbidden {
					http.Error(w, `{"error":"forbidden","message":"无权限访问"}`, http.StatusForbidden)
				} else {
					http.Error(w, `{"error":"internal_error","message":"鉴权失败"}`, http.StatusInternalServerError)
				}
				return
			}

			ctx := context.WithValue(r.Context(), ClaimsKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireAnyRelation 返回要求任意一个指定关系的中间件
func (m *Middleware) RequireAnyRelation(relations ...string) MiddlewareFunc {
	return m.RequireAnyRelationOn(relations, "*", "*")
}

// RequireAnyRelationOn 返回要求任意一个指定关系的中间件（指定资源）
func (m *Middleware) RequireAnyRelationOn(relations []string, objectType, objectID string) MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 1. 认证
			claims, err := m.authenticate(r)
			if err != nil {
				http.Error(w, `{"error":"unauthorized","message":"未登录或登录已过期"}`, http.StatusUnauthorized)
				return
			}

			// 2. 鉴权（任意一个关系即可）
			if err := m.authorizeAny(r.Context(), claims, relations, objectType, objectID); err != nil {
				if err == errForbidden {
					http.Error(w, `{"error":"forbidden","message":"无权限访问"}`, http.StatusForbidden)
				} else {
					http.Error(w, `{"error":"internal_error","message":"鉴权失败"}`, http.StatusInternalServerError)
				}
				return
			}

			ctx := context.WithValue(r.Context(), ClaimsKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

var errForbidden = &forbiddenError{}

type forbiddenError struct{}

func (e *forbiddenError) Error() string { return "forbidden" }

// authenticate 认证：验证用户 token
func (m *Middleware) authenticate(r *http.Request) (*token.Claims, error) {
	tokenStr := extractToken(r)
	if tokenStr == "" {
		return nil, token.ErrMissingClaims
	}

	return m.interpreter.Interpret(r.Context(), tokenStr)
}

// authorize 鉴权：检查单个关系
func (m *Middleware) authorize(ctx context.Context, claims *token.Claims, relation, objectType, objectID string) error {
	if m.checker == nil {
		return errForbidden
	}

	permitted, err := m.checker.Check(ctx, claims, relation, objectType, objectID)
	if err != nil {
		return err
	}
	if !permitted {
		return errForbidden
	}
	return nil
}

// authorizeAny 鉴权：检查任意一个关系
func (m *Middleware) authorizeAny(ctx context.Context, claims *token.Claims, relations []string, objectType, objectID string) error {
	if m.checker == nil {
		return errForbidden
	}

	for _, relation := range relations {
		permitted, err := m.checker.Check(ctx, claims, relation, objectType, objectID)
		if err != nil {
			continue
		}
		if permitted {
			return nil
		}
	}
	return errForbidden
}

// extractToken 从请求中提取 token
func extractToken(r *http.Request) string {
	authorization := r.Header.Get("Authorization")
	if authorization == "" {
		return ""
	}

	if strings.HasPrefix(authorization, "Bearer ") {
		return authorization[7:]
	}
	return authorization
}

// GetClaims 从 context 中获取用户身份信息
func GetClaims(ctx context.Context) *token.Claims {
	claims, ok := ctx.Value(ClaimsKey).(*token.Claims)
	if !ok {
		return nil
	}
	return claims
}

// GetOpenID 从 context 中获取用户 OpenID
func GetOpenID(ctx context.Context) string {
	claims := GetClaims(ctx)
	if claims == nil {
		return ""
	}
	return claims.Subject
}
