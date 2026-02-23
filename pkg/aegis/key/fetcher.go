package key

import (
	"context"
)

// Fetcher 密钥拉取接口
type Fetcher interface {
	Fetch(ctx context.Context, id string) ([][]byte, error)
}

// FetcherFunc 函数式 Fetcher
type FetcherFunc func(ctx context.Context, id string) ([][]byte, error)

// Fetch 实现 Fetcher 接口
func (f FetcherFunc) Fetch(ctx context.Context, id string) ([][]byte, error) {
	return f(ctx, id)
}

// StaticFetcher 静态密钥 Fetcher（忽略 id）
type StaticFetcher struct {
	keys [][]byte
}

// NewStaticFetcher 创建静态 Fetcher
func NewStaticFetcher(keys ...[]byte) *StaticFetcher {
	return &StaticFetcher{keys: keys}
}

// Fetch 返回静态密钥
func (f *StaticFetcher) Fetch(_ context.Context, _ string) ([][]byte, error) {
	if len(f.keys) == 0 {
		return nil, ErrNotFound
	}
	return f.keys, nil
}
