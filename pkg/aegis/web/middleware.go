// Package web 提供 Aegis 认证和鉴权中间件
//
// 使用示例：
//
//	factory := web.NewFactory("http://auth.example.com", encryptKeyStore, catKeyStore)
//	mw := factory.WithAudience("my-service-id")
//
//	r.Use(mw.RequireAuth())                      // 仅认证
//	r.GET("/admin", mw.RequireRelation("admin")) // 认证 + 鉴权
package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/heliannuuthus/helios/pkg/aegis/key"
	tokendef "github.com/heliannuuthus/helios/pkg/aegis/utils/token"
	"github.com/heliannuuthus/helios/pkg/logger"
)

// ContextKey 上下文 key 类型
type ContextKey string

const (
	// ClaimsKey 用户身份信息在 context 中的 key
	ClaimsKey ContextKey = "aegis:user"

	// AuthorizationHeader Authorization 请求头
	AuthorizationHeader = "Authorization"

	// ChallengeTokenHeader X-Challenge-Token header 名称（参考 RFC 9449 DPoP 独立 header 模式）
	ChallengeTokenHeader = "X-Challenge-Token"
)

// Factory 中间件工厂
type Factory struct {
	interpreter *Interpreter
	checker     *RelationChecker
}

// NewFactory 创建中间件工厂
// signKeyProvider 内部通过 endpoint 自动创建 PublicKeyFetcher。
func NewFactory(
	endpoint string,
	encryptKeyProvider key.Provider,
	catKeyProvider key.Provider,
) *Factory {
	signKeyProvider := key.NewPublicKeyFetcher(endpoint)
	return &Factory{
		interpreter: NewInterpreter(signKeyProvider, encryptKeyProvider),
		checker:     NewRelationChecker(endpoint, catKeyProvider),
	}
}

// WithAudience 为特定 audience 创建中间件
func (f *Factory) WithAudience(audience string) *Middleware {
	return &Middleware{
		interpreter: f.interpreter,
		checker:     f.checker,
		audience:    audience,
	}
}

// Middleware Aegis 中间件
type Middleware struct {
	interpreter *Interpreter
	checker     *RelationChecker
	audience    string
}

// MiddlewareFunc 中间件函数类型
type MiddlewareFunc func(next http.Handler) http.Handler

// RequireAuth 返回要求认证的中间件
func (m *Middleware) RequireAuth() MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tc, err := m.authenticate(r)
			if err != nil {
				writeJSONError(w, http.StatusUnauthorized, "unauthorized", "未登录或登录已过期")
				return
			}

			ctx := context.WithValue(r.Context(), ClaimsKey, tc)
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
			tc, err := m.authenticate(r)
			if err != nil {
				writeJSONError(w, http.StatusUnauthorized, "unauthorized", "未登录或登录已过期")
				return
			}

			if err := m.authorize(r.Context(), tc, relation, objectType, objectID); err != nil {
				if errors.Is(err, errForbidden) {
					writeJSONError(w, http.StatusForbidden, "forbidden", "无权限访问")
				} else {
					writeJSONError(w, http.StatusInternalServerError, "internal_error", "鉴权失败")
				}
				return
			}

			ctx := context.WithValue(r.Context(), ClaimsKey, tc)
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
			tc, err := m.authenticate(r)
			if err != nil {
				writeJSONError(w, http.StatusUnauthorized, "unauthorized", "未登录或登录已过期")
				return
			}

			if err := m.authorizeAny(r.Context(), tc, relations, objectType, objectID); err != nil {
				if errors.Is(err, errForbidden) {
					writeJSONError(w, http.StatusForbidden, "forbidden", "无权限访问")
				} else {
					writeJSONError(w, http.StatusInternalServerError, "internal_error", "鉴权失败")
				}
				return
			}

			ctx := context.WithValue(r.Context(), ClaimsKey, tc)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

var errForbidden = errors.New("forbidden")

// authenticate 认证：验证 Authorization token，可选解析 X-Challenge-Token，组装 TokenContext
func (m *Middleware) authenticate(r *http.Request) (*TokenContext, error) {
	tokenStr := extractBearerToken(r)
	if tokenStr == "" {
		return nil, tokendef.ErrMissingClaims
	}

	t, err := m.interpreter.Interpret(r.Context(), tokenStr)
	if err != nil {
		return nil, err
	}

	var ct *tokendef.ChallengeToken
	if challengeStr := extractChallengeToken(r); challengeStr != "" {
		parsed, err := m.interpreter.Verify(r.Context(), challengeStr)
		if err != nil {
			logger.Warnf("[Auth] X-Challenge-Token 验证失败: %v", err)
		} else if xt, ok := parsed.(*tokendef.ChallengeToken); ok {
			ct = xt
		} else {
			logger.Warnf("[Auth] X-Challenge-Token 类型断言失败: %T", parsed)
		}
	}

	return NewTokenContext(t, ct)
}

// accessToken 从 TokenContext 中提取 access token（用于鉴权）
func (m *Middleware) accessToken(tc *TokenContext) tokendef.Token {
	return accessTokenFrom(tc)
}

// authorize 鉴权：检查单个关系
func (m *Middleware) authorize(ctx context.Context, tc *TokenContext, relation, objectType, objectID string) error {
	if m.checker == nil {
		return errForbidden
	}

	t := m.accessToken(tc)
	if t == nil {
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
func (m *Middleware) authorizeAny(ctx context.Context, tc *TokenContext, relations []string, objectType, objectID string) error {
	if m.checker == nil {
		return errForbidden
	}

	t := m.accessToken(tc)
	if t == nil {
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

func writeJSONError(w http.ResponseWriter, statusCode int, errType, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(statusCode)
	if _, err := fmt.Fprintf(w, `{"error":%q,"message":%q}`, errType, message); err != nil {
		return
	}
}

func extractBearerToken(r *http.Request) string {
	return TrimBearer(r.Header.Get(AuthorizationHeader))
}

func extractChallengeToken(r *http.Request) string {
	return TrimBearer(r.Header.Get(ChallengeTokenHeader))
}

// TrimBearer 去除 "Bearer " 前缀，返回 token 本体；无前缀则返回空串。
func TrimBearer(s string) string {
	if len(s) > 7 && strings.EqualFold(s[:7], "Bearer ") {
		return s[7:]
	}
	return ""
}
