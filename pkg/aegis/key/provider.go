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

// SingleOf 单密钥加载函数，实现 Provider 接口。
type SingleOf func(ctx context.Context, id string) ([]byte, error)

func (f SingleOf) OneOfKey(ctx context.Context, id string) ([]byte, error) {
	return f(ctx, id)
}

func (f SingleOf) AllOfKey(ctx context.Context, id string) ([][]byte, error) {
	b, err := f(ctx, id)
	if err != nil {
		return nil, err
	}
	return [][]byte{b}, nil
}

// MultiOf 多密钥加载函数，实现 Provider 接口。
type MultiOf func(ctx context.Context, id string) ([][]byte, error)

func (f MultiOf) OneOfKey(ctx context.Context, id string) ([]byte, error) {
	keys, err := f(ctx, id)
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, ErrNotFound
	}
	return keys[0], nil
}

func (f MultiOf) AllOfKey(ctx context.Context, id string) ([][]byte, error) {
	return f(ctx, id)
}
