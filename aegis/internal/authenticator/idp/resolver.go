package idp

import "context"

// contextKey 用于在 context 中传递 appID
type contextKey struct{}

// WithAppID 将 appID 注入 context
func WithAppID(ctx context.Context, appID string) context.Context {
	return context.WithValue(ctx, contextKey{}, appID)
}

// AppIDFromContext 从 context 中提取 appID
func AppIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(contextKey{}).(string); ok {
		return v
	}
	return ""
}
