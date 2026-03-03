package web

import (
	tokendef "github.com/heliannuuthus/helios/pkg/aegis/utils/token"
)

// TokenContext 聚合中间件解密后的 token 产物。
// UAT 和 SAT 互斥（一个请求的 AccessToken 只能是其一），ChallengeToken 可选。
type TokenContext struct {
	userAccessToken    *tokendef.UserAccessToken
	serviceAccessToken *tokendef.ServiceAccessToken
	challengeToken     *tokendef.ChallengeToken
}

// UserAccessToken 返回用户访问令牌（含 UserInfo），无则返回 nil。
func (tc *TokenContext) UserAccessToken() *tokendef.UserAccessToken {
	return tc.userAccessToken
}

// ServiceAccessToken 返回服务访问令牌（M2M），无则返回 nil。
func (tc *TokenContext) ServiceAccessToken() *tokendef.ServiceAccessToken {
	return tc.serviceAccessToken
}

// ChallengeToken 返回验证凭证（来自 X-Challenge-Token header），无则返回 nil。
func (tc *TokenContext) ChallengeToken() *tokendef.ChallengeToken {
	return tc.challengeToken
}

// NewTokenContext 从已解析的 token.Token 构造 TokenContext。
func NewTokenContext(t tokendef.Token) *TokenContext {
	tc := &TokenContext{}
	switch v := t.(type) {
	case *tokendef.UserAccessToken:
		tc.userAccessToken = v
	case *tokendef.ServiceAccessToken:
		tc.serviceAccessToken = v
	case *tokendef.ChallengeToken:
		tc.challengeToken = v
	}
	return tc
}

// WithChallenge 追加 ChallengeToken 到已有 TokenContext。
func (tc *TokenContext) WithChallenge(ct *tokendef.ChallengeToken) {
	tc.challengeToken = ct
}
