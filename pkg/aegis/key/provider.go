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

// Fetcher 远程获取密钥的接口
type Fetcher interface {
	Fetch(ctx context.Context, id string) ([][]byte, error)
}

// Loader 本地加载密钥的接口
type Loader interface {
	Load(ctx context.Context, id string) ([][]byte, error)
}
