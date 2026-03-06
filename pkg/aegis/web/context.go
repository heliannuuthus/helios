package web

import (
	"context"

	tokendef "github.com/heliannuuthus/helios/pkg/aegis/utils/token"
)

// TokenContext 聚合中间件解密后的 token 产物。
// AccessToken 为 UAT 或 SAT（互斥），ChallengeToken 可选。
type TokenContext struct {
	AccessToken    tokendef.AccessToken
	ChallengeToken *tokendef.ChallengeToken
}

// GetTokenContext 从标准 context 中获取 TokenContext。
func GetTokenContext(ctx context.Context) *TokenContext {
	tc, _ := ctx.Value(ClaimsKey).(*TokenContext)
	return tc
}
