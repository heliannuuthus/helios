package key

import (
	"context"
)

// Provider 密钥提供者接口
type Provider interface {
	OneOfKey(ctx context.Context, id string) ([]byte, error)
	AllOfKey(ctx context.Context, id string) ([][]byte, error)
}
