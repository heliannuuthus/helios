package helpers

import "context"

type contextKey int

const (
	remoteIPKey contextKey = iota
)

// WithRemoteIP 将客户端 IP 写入 context
func WithRemoteIP(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, remoteIPKey, ip)
}

// RemoteIPFrom 从 context 中读取客户端 IP
func RemoteIPFrom(ctx context.Context) string {
	ip, ok := ctx.Value(remoteIPKey).(string)
	if !ok {
		return ""
	}
	return ip
}
