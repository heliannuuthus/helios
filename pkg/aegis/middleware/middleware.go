// Package middleware 提供 Aegis 认证和鉴权中间件
//
// 使用示例：
//
//	// 创建 KeyStore
//	signKeyStore := key.NewStore(signFetcher, watcher)
//	encryptKeyStore := key.NewStore(encryptFetcher, watcher)
//	catKeyStore := key.NewStore(catFetcher, watcher)
//
//	// 创建全局 Factory
//	factory := middleware.NewFactory("http://auth.example.com", signKeyStore, encryptKeyStore, catKeyStore)
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
	"fmt"
	"net/http"
	"strings"

	"github.com/heliannuuthus/helios/pkg/aegis/authz"
	"github.com/heliannuuthus/helios/pkg/aegis/key"
	"github.com/heliannuuthus/helios/pkg/aegis/token"
)

// ContextKey 上下文 key 类型
type ContextKey string

const (
	// ClaimsKey 用户身份信息在 context 中的 key
	ClaimsKey ContextKey = "aegis:claims"
)

// Factory 中间件工厂
type Factory struct {
	signKeyStore    *key.Store
	encryptKeyStore *key.Store
	catKeyStore     *key.Store
	authzClient     *authz.Client
}

// NewFactory 创建中间件工厂
func NewFactory(
	endpoint string,
	signKeyStore *key.Store,
	encryptKeyStore *key.Store,
	catKeyStore *key.Store,
) *Factory {
	return &Factory{
		signKeyStore:    signKeyStore,
		encryptKeyStore: encryptKeyStore,
		catKeyStore:     catKeyStore,
		authzClient:     authz.NewClient(endpoint, catKeyStore),
	}
}

// WithAudience 为特定 audience 创建中间件
func (f *Factory) WithAudience(audience string) *Middleware {
	interp := token.NewInterpreter(f.signKeyStore, f.encryptKeyStore)
	return &Middleware{
		interpreter: interp,
		authzClient: f.authzClient,
		audience:    audience,
	}
}

// Middleware Aegis 中间件
type Middleware struct {
	interpreter *token.Interpreter
	authzClient *authz.Client
	audience    string
}

// MiddlewareFunc 中间件函数类型
type MiddlewareFunc func(next http.Handler) http.Handler

// RequireAuth 返回要求认证的中间件
func (m *Middleware) RequireAuth() MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, err := m.authenticate(r)
			if err != nil {
				writeJSONError(w, http.StatusUnauthorized, "unauthorized", "未登录或登录已过期")
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
			claims, err := m.authenticate(r)
			if err != nil {
				writeJSONError(w, http.StatusUnauthorized, "unauthorized", "未登录或登录已过期")
				return
			}

			if err := m.authorize(r.Context(), claims, relation, objectType, objectID); err != nil {
				if errors.Is(err, errForbidden) {
					writeJSONError(w, http.StatusForbidden, "forbidden", "无权限访问")
				} else {
					writeJSONError(w, http.StatusInternalServerError, "internal_error", "鉴权失败")
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
			claims, err := m.authenticate(r)
			if err != nil {
				writeJSONError(w, http.StatusUnauthorized, "unauthorized", "未登录或登录已过期")
				return
			}

			if err := m.authorizeAny(r.Context(), claims, relations, objectType, objectID); err != nil {
				if errors.Is(err, errForbidden) {
					writeJSONError(w, http.StatusForbidden, "forbidden", "无权限访问")
				} else {
					writeJSONError(w, http.StatusInternalServerError, "internal_error", "鉴权失败")
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
func (m *Middleware) authenticate(r *http.Request) (token.Token, error) {
	tokenStr := extractToken(r)
	if tokenStr == "" {
		return nil, token.ErrMissingClaims
	}

	t, err := m.interpreter.Interpret(r.Context(), tokenStr)
	if err != nil {
		return nil, err
	}

	if m.audience != "" && t.GetAudience() != m.audience {
		return nil, fmt.Errorf("%w: expected %s, got %s", token.ErrUnsupportedAudience, m.audience, t.GetAudience())
	}

	return t, nil
}

// authorize 鉴权：检查单个关系
func (m *Middleware) authorize(ctx context.Context, t token.Token, relation, objectType, objectID string) error {
	if m.authzClient == nil {
		return errForbidden
	}

	permitted, err := m.authzClient.Check(ctx, t, relation, objectType, objectID)
	if err != nil {
		return err
	}
	if !permitted {
		return errForbidden
	}
	return nil
}

// authorizeAny 鉴权：检查任意一个关系
func (m *Middleware) authorizeAny(ctx context.Context, t token.Token, relations []string, objectType, objectID string) error {
	if m.authzClient == nil {
		return errForbidden
	}

	var lastErr error
	for _, relation := range relations {
		permitted, err := m.authzClient.Check(ctx, t, relation, objectType, objectID)
		if err != nil {
			lastErr = err
			continue
		}
		if permitted {
			return nil
		}
	}
	if lastErr != nil {
		return fmt.Errorf("%w: %w", errForbidden, lastErr)
	}
	return errForbidden
}

func writeJSONError(w http.ResponseWriter, statusCode int, errType, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(statusCode)
	if _, err := fmt.Fprintf(w, `{"error":%q,"message":%q}`, errType, message); err != nil {
		return
	}
}

func extractToken(r *http.Request) string {
	authorization := r.Header.Get("Authorization")
	if authorization == "" {
		return ""
	}

	if strings.HasPrefix(authorization, "Bearer ") {
		return authorization[7:]
	}
	return ""
}

// GetToken 从 context 中获取验证后的 Token
func GetToken(ctx context.Context) token.Token {
	t, ok := ctx.Value(ClaimsKey).(token.Token)
	if !ok {
		return nil
	}
	return t
}

// GetOpenID 从 context 中获取用户标识
func GetOpenID(ctx context.Context) string {
	t := GetToken(ctx)
	if t == nil {
		return ""
	}
	if uat, ok := t.(*token.UserAccessToken); ok && uat.HasUser() {
		return uat.GetOpenID()
	}
	return ""
}
