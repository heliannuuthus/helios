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
	"fmt"
	"net/http"
	"strings"

	"github.com/heliannuuthus/helios/pkg/aegis/checker"
	"github.com/heliannuuthus/helios/pkg/aegis/interpreter"
	"github.com/heliannuuthus/helios/pkg/aegis/keys"
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
	signKeyProvider    keys.PublicKeyProvider    // 验证 UAT 签名（公钥）
	encryptKeyProvider keys.SymmetricKeyProvider // 解密 UAT footer（对称密钥）
	catSignKeyProvider keys.SecretKeyProvider    // 签发 CAT（私钥）
	checker            *checker.Checker
}

// NewFactory 创建中间件工厂
// ctx: 用于初始化
// endpoint: Aegis 服务端点（如 http://auth.example.com）
// publicKeyProvider: 公钥提供者（用于验证 UAT 签名）
// symmetricKeyProvider: 对称密钥提供者（用于解密 footer）
// secretKeyProvider: 私钥提供者（用于签发 CAT）
func NewFactory(
	endpoint string,
	publicKeyProvider keys.PublicKeyProvider,
	symmetricKeyProvider keys.SymmetricKeyProvider,
	secretKeyProvider keys.SecretKeyProvider,
) *Factory {
	return &Factory{
		signKeyProvider:    publicKeyProvider,
		encryptKeyProvider: symmetricKeyProvider,
		catSignKeyProvider: secretKeyProvider,
		checker:            checker.NewChecker(endpoint, secretKeyProvider),
	}
}

// WithAudience 为特定 audience 创建中间件
// audience: 服务 ID（用于 token 验证）
func (f *Factory) WithAudience(audience string) *Middleware {
	interp := interpreter.NewInterpreter(f.signKeyProvider, f.encryptKeyProvider)
	return &Middleware{
		interpreter: interp,
		checker:     f.checker,
		audience:    audience,
	}
}

// Middleware Aegis 中间件
type Middleware struct {
	interpreter *interpreter.Interpreter
	checker     *checker.Checker
	audience    string // 期望的 audience（用于 token 验证）
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
			// 1. 认证
			claims, err := m.authenticate(r)
			if err != nil {
				writeJSONError(w, http.StatusUnauthorized, "unauthorized", "未登录或登录已过期")
				return
			}

			// 2. 鉴权
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
			// 1. 认证
			claims, err := m.authenticate(r)
			if err != nil {
				writeJSONError(w, http.StatusUnauthorized, "unauthorized", "未登录或登录已过期")
				return
			}

			// 2. 鉴权（任意一个关系即可）
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

// ErrUnsupportedAudience audience 不支持错误
var ErrUnsupportedAudience = errors.New("unsupported audience")

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

	// 验证 audience（如果配置了）
	if m.audience != "" && t.GetAudience() != m.audience {
		return nil, fmt.Errorf("%w: expected %s, got %s", ErrUnsupportedAudience, m.audience, t.GetAudience())
	}

	return t, nil
}

// authorize 鉴权：检查单个关系
func (m *Middleware) authorize(ctx context.Context, t token.Token, relation, objectType, objectID string) error {
	if m.checker == nil {
		return errForbidden
	}

	permitted, err := m.checker.Check(ctx, t, relation, objectType, objectID)
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
	if m.checker == nil {
		return errForbidden
	}

	var lastErr error
	for _, relation := range relations {
		permitted, err := m.checker.Check(ctx, t, relation, objectType, objectID)
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

// writeJSONError 写入统一格式的 JSON 错误响应
func writeJSONError(w http.ResponseWriter, statusCode int, errType, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(statusCode)
	// 使用 fmt.Fprintf 避免 JSON 注入风险
	// HTTP 响应写入失败通常无法恢复（客户端已断开连接），忽略错误是标准做法
	if _, err := fmt.Fprintf(w, `{"error":%q,"message":%q}`, errType, message); err != nil {
		// 写入失败时，连接可能已断开，无需额外处理
		return
	}
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

// GetToken 从 context 中获取验证后的 Token
func GetToken(ctx context.Context) token.Token {
	t, ok := ctx.Value(ClaimsKey).(token.Token)
	if !ok {
		return nil
	}
	return t
}

// GetOpenID 从 context 中获取用户 OpenID
func GetOpenID(ctx context.Context) string {
	t := GetToken(ctx)
	if t == nil {
		return ""
	}
	if uat, ok := token.AsUAT(t); ok && uat.HasUser() {
		return uat.GetOpenID()
	}
	return ""
}
