package key

import (
	"context"
	"errors"
)

var ErrNotFound = errors.New("key not found")

// Provider 密钥提供者接口
type Provider interface {
	OneOfKey(ctx context.Context, id string) ([]byte, error)
	AllOfKey(ctx context.Context, id string) ([][]byte, error)
}

// Subscribable 支持订阅密钥变更
type Subscribable interface {
	Subscribe(id string, callback func(keys [][]byte))
}
