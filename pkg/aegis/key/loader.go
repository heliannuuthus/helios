package key

import "context"

// LoadKeyFunc 按 id 加载单个密钥的函数式 Loader，同时实现 Provider 接口
type LoadKeyFunc func(ctx context.Context, id string) ([]byte, error)

func (f LoadKeyFunc) Load(ctx context.Context, id string) ([][]byte, error) {
	k, err := f(ctx, id)
	if err != nil {
		return nil, err
	}
	return [][]byte{k}, nil
}

func (f LoadKeyFunc) OneOfKey(ctx context.Context, id string) ([]byte, error) {
	return f(ctx, id)
}

func (f LoadKeyFunc) AllOfKey(ctx context.Context, id string) ([][]byte, error) {
	return f.Load(ctx, id)
}

// LoadKeysFunc 按 id 加载多个密钥的函数式 Loader，同时实现 Provider 接口
type LoadKeysFunc func(ctx context.Context, id string) ([][]byte, error)

func (f LoadKeysFunc) Load(ctx context.Context, id string) ([][]byte, error) {
	return f(ctx, id)
}

func (f LoadKeysFunc) OneOfKey(ctx context.Context, id string) ([]byte, error) {
	keys, err := f(ctx, id)
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, ErrNotFound
	}
	return keys[0], nil
}

func (f LoadKeysFunc) AllOfKey(ctx context.Context, id string) ([][]byte, error) {
	return f(ctx, id)
}
