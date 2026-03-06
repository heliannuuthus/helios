package web

import (
	"context"

	"github.com/heliannuuthus/helios/pkg/aegis/utils/relation"
	tokendef "github.com/heliannuuthus/helios/pkg/aegis/utils/token"
)

// TokenContext 聚合中间件解密后的 token 产物。
// AccessToken 为 UAT 或 SAT（互斥），ChallengeToken 可选。
type TokenContext struct {
	AccessToken    tokendef.AccessToken
	ChallengeToken *tokendef.ChallengeToken
}

type tokenContextKey struct{}

// GetTokenContext 从标准 context 中获取 TokenContext。
func GetTokenContext(ctx context.Context) *TokenContext {
	tc, _ := ctx.Value(tokenContextKey{}).(*TokenContext) //nolint:errcheck // type assertion ok
	return tc
}

// GetTokenContext 从标准 context 中获取 TokenContext。
func WithTokenContext(ctx context.Context, tc *TokenContext) context.Context {
	return context.WithValue(ctx, tokenContextKey{}, tc)
}

type resolverKey struct{}

func WithRelationResolver(ctx context.Context, r *relation.Resolver) context.Context {
	return context.WithValue(ctx, resolverKey{}, r)
}

func GetRelationResolver(ctx context.Context) *relation.Resolver {
	r, _ := ctx.Value(resolverKey{}).(*relation.Resolver) //nolint:errcheck // type assertion ok
	return r
}
