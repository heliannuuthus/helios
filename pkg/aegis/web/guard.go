package web

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/go-json-experiment/json"

	"github.com/heliannuuthus/helios/pkg/aegis/utils/client"
	tokendef "github.com/heliannuuthus/helios/pkg/aegis/utils/token"
	"github.com/heliannuuthus/helios/pkg/logger"
)

// Authenticate 从 http.Request 提取并验证 token，返回 TokenContext。
// 框架无关，供各 web 框架适配器调用。
func Authenticate(r *http.Request) (*TokenContext, error) {
	tokenStr := client.TrimBearer(r.Header.Get(client.AuthorizationHeader))
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

	ct := parseChallengeToken(r)

	at, ok := t.(tokendef.AccessToken)
	if !ok {
		return nil, fmt.Errorf("token type %T does not implement AccessToken", t)
	}

	return &TokenContext{AccessToken: at, ChallengeToken: ct}, nil
}

func parseChallengeToken(r *http.Request) *tokendef.ChallengeToken {
	manager := GetTokenManager()
	if manager == nil {
		return nil
	}

	challengeStr := client.TrimBearer(r.Header.Get(client.ChallengeTokenHeader))
	if challengeStr == "" {
		return nil
	}

	challengeUnsafe, err := tokendef.UnsafeParseToken(challengeStr)
	if err != nil {
		logger.Warnf("[Auth] X-Challenge-Token 解析失败: %v", err)
		return nil
	}

	cAud, err := tokendef.GetAudience(challengeUnsafe)
	if err != nil {
		logger.Warnf("[Auth] X-Challenge-Token audience 缺失: %v", err)
		return nil
	}

	cClientID, err := tokendef.GetClientID(challengeUnsafe)
	if err != nil {
		logger.Warnf("[Auth] X-Challenge-Token clientID 缺失: %v", err)
		return nil
	}

	parsed, err := manager.Decryptor(cAud).Verifier(cClientID).Verify(r.Context(), challengeStr)
	if err != nil {
		logger.Warnf("[Auth] X-Challenge-Token 验证失败: %v", err)
		return nil
	}

	cToken, err := tokendef.ParseToken(parsed, tokendef.DetectType(parsed))
	if err != nil {
		logger.Warnf("[Auth] X-Challenge-Token 类型解析失败: %v", err)
		return nil
	}

	xt, ok := cToken.(*tokendef.ChallengeToken)
	if !ok {
		logger.Warnf("[Auth] X-Challenge-Token 类型断言失败: %T", cToken)
		return nil
	}

	return xt
}

// ParseBody 从 http.Request 提取 body 参数（JSON / form）。
func ParseBody(r *http.Request) map[string]any {
	if r.Body == nil {
		return nil
	}

	ct := r.Header.Get("Content-Type")
	switch {
	case strings.HasPrefix(ct, "application/json"):
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return nil
		}
		r.Body = io.NopCloser(strings.NewReader(string(body)))
		var m map[string]any
		if err := json.Unmarshal(body, &m); err != nil {
			return nil
		}
		return m

	case strings.HasPrefix(ct, "application/x-www-form-urlencoded"),
		strings.HasPrefix(ct, "multipart/form-data"):
		if err := r.ParseForm(); err != nil {
			return nil
		}
		m := make(map[string]any, len(r.PostForm))
		for k, v := range r.PostForm {
			if len(v) > 0 {
				m[k] = v[0]
			}
		}
		return m
	}

	return nil
}
