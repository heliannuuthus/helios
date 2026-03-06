// Package web 提供 Aegis 认证和鉴权中间件
//
// 使用示例：
//
//	web.InitManager("http://auth.example.com", seedProvider)
//	factory := web.NewFactory()
//	mw := factory.WithAudience("my-service-id")
//
//	guard := guard.NewGinGuard(mw)
//	r.Use(guard.Require())
//	r.GET("/admin", guard.Require(web.Relation("admin")))
package web

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	tokendef "github.com/heliannuuthus/helios/pkg/aegis/utils/token"
	"github.com/heliannuuthus/helios/pkg/logger"
)

// ContextKey 上下文 key 类型
type ContextKey string

const (
	// ClaimsKey 用户身份信息在 context 中的 key
	ClaimsKey ContextKey = "###aegis@user###"

	// AuthorizationHeader Authorization 请求头
	AuthorizationHeader = "Authorization"

	// ChallengeTokenHeader X-Challenge-Token header 名称（参考 RFC 9449 DPoP 独立 header 模式）
	ChallengeTokenHeader = "X-Challenge-Token"
)

// Factory 中间件工厂，通过 GetTokenManager() 获取全局 Manager。
type Factory struct{}

// NewFactory 创建中间件工厂。
func NewFactory() *Factory {
	return &Factory{}
}

// WithAudience 为特定 audience 创建中间件。
func (f *Factory) WithAudience(audience string) *Middleware {
	return &Middleware{audience: audience}
}

// Middleware Aegis 认证中间件（框架无关）。
type Middleware struct {
	audience string
}

// Authenticate 认证：验证 Authorization token，可选解析 X-Challenge-Token，返回 TokenContext。
func (m *Middleware) Authenticate(r *http.Request) (*TokenContext, error) {
	tokenStr := extractBearerToken(r)
	if tokenStr == "" {
		return nil, tokendef.ErrMissingClaims
	}

	manager := GetTokenManager()
	if manager == nil {
		return nil, errors.New("token manager not initialized")
	}

	unsafeToken, err := tokendef.UnsafeParseToken(tokenStr)
	if err != nil {
		return nil, err
	}

	audience, err := tokendef.GetAudience(unsafeToken)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", tokendef.ErrMissingClaims, err)
	}

	t, err := manager.Decryptor(audience).Interpret(r.Context(), tokenStr)
	if err != nil {
		return nil, err
	}

	var ct *tokendef.ChallengeToken
	if challengeStr := extractChallengeToken(r); challengeStr != "" {
		challengeUnsafe, cErr := tokendef.UnsafeParseToken(challengeStr)
		if cErr != nil {
			logger.Warnf("[Auth] X-Challenge-Token 解析失败: %v", cErr)
		} else {
			cAud, cErr := tokendef.GetAudience(challengeUnsafe)
			if cErr != nil {
				logger.Warnf("[Auth] X-Challenge-Token audience 缺失: %v", cErr)
			} else {
				cClientID, cErr := tokendef.GetClientID(challengeUnsafe)
				if cErr != nil {
					logger.Warnf("[Auth] X-Challenge-Token clientID 缺失: %v", cErr)
				} else {
					parsed, cErr := manager.Decryptor(cAud).Verifier(cClientID).Verify(r.Context(), challengeStr)
					if cErr != nil {
						logger.Warnf("[Auth] X-Challenge-Token 验证失败: %v", cErr)
					} else {
						cToken, cErr := tokendef.ParseToken(parsed, tokendef.DetectType(parsed))
						if cErr != nil {
							logger.Warnf("[Auth] X-Challenge-Token 类型解析失败: %v", cErr)
						} else if xt, ok := cToken.(*tokendef.ChallengeToken); ok {
							ct = xt
						} else {
							logger.Warnf("[Auth] X-Challenge-Token 类型断言失败: %T", cToken)
						}
					}
				}
			}
		}
	}

	at, ok := t.(tokendef.AccessToken)
	if !ok {
		return nil, fmt.Errorf("token type %T does not implement AccessToken", t)
	}

	return &TokenContext{AccessToken: at, ChallengeToken: ct}, nil
}

var (
	ErrUnauthorized = errors.New("unauthorized")
	ErrForbidden    = errors.New("forbidden")
)

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
