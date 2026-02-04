// Package middleware 提供 Aegis 认证和鉴权中间件
//
// 使用示例：
//
//	// 创建全局 Factory
//	factory, err := middleware.NewFactory(ctx, "http://auth.example.com", publicKeyProvider, symmetricKeyProvider, secretKeyProvider)
//
//	// 为特定 audience 创建中间件
//	mw := factory.WithAudience("my-service-id")
//
//	r.Use(mw.RequireAuth())                      // 仅认证
//	r.GET("/admin", mw.RequireRelation("admin")) // 认证 + 鉴权
package middleware

import (
	"context"
	"errors"
	"net/http"
	"strings"

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
	signKeyProvider    token.PublicKeyProvider    // 验证 UAT 签名（公钥）
	encryptKeyProvider token.SymmetricKeyProvider // 解密 UAT footer（对称密钥）
	catSignKeyProvider token.SecretKeyProvider    // 签发 CAT（私钥）
	checker            *token.Checker
}

// NewFactory 创建中间件工厂
// ctx: 用于初始化
// endpoint: Aegis 服务端点（如 http://auth.example.com）
// publicKeyProvider: 公钥提供者（用于验证 UAT 签名）
// symmetricKeyProvider: 对称密钥提供者（用于解密 footer）
// secretKeyProvider: 私钥提供者（用于签发 CAT）
func NewFactory(
	endpoint string,
	publicKeyProvider token.PublicKeyProvider,
	symmetricKeyProvider token.SymmetricKeyProvider,
	secretKeyProvider token.SecretKeyProvider,
) *Factory {
	return &Factory{
		signKeyProvider:    publicKeyProvider,
		encryptKeyProvider: symmetricKeyProvider,
		catSignKeyProvider: secretKeyProvider,
		checker:            token.NewChecker(endpoint, secretKeyProvider),
	}
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
				if errors.Is(err, errForbidden) {
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
				if errors.Is(err, errForbidden) {
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
func (m *Middleware) authenticate(r *http.Request) (*token.VerifiedToken, error) {
	tokenStr := extractToken(r)
	if tokenStr == "" {
		return nil, token.ErrMissingClaims
	}

	return m.interpreter.Interpret(r.Context(), tokenStr)
}

// authorize 鉴权：检查单个关系
func (m *Middleware) authorize(ctx context.Context, vt *token.VerifiedToken, relation, objectType, objectID string) error {
	if m.checker == nil {
		return errForbidden
	}

	permitted, err := m.checker.Check(ctx, vt, relation, objectType, objectID)
	if err != nil {
		return err
	}
	if !permitted {
		return errForbidden
	}
	return nil
}

// authorizeAny 鉴权：检查任意一个关系
func (m *Middleware) authorizeAny(ctx context.Context, vt *token.VerifiedToken, relations []string, objectType, objectID string) error {
	if m.checker == nil {
		return errForbidden
	}

	for _, relation := range relations {
		permitted, err := m.checker.Check(ctx, vt, relation, objectType, objectID)
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

// GetVerifiedToken 从 context 中获取验证后的 Token
func GetVerifiedToken(ctx context.Context) *token.VerifiedToken {
	vt, ok := ctx.Value(ClaimsKey).(*token.VerifiedToken)
	if !ok {
		return nil
	}
	return vt
}

// GetOpenID 从 context 中获取用户 OpenID
func GetOpenID(ctx context.Context) string {
	vt := GetVerifiedToken(ctx)
	if vt == nil || vt.User == nil {
		return ""
	}
	return vt.User.Subject
}
