package key

import (
	"context"
	"sync"

	"github.com/heliannuuthus/helios/pkg/logger"
)

// Store 密钥存储，实现 Provider 接口
type Store struct {
	name    string
	fetcher Fetcher
	watcher Watcher

	mu    sync.RWMutex
	cache map[string][][]byte
}

// NewStore 创建 Store
func NewStore(fetcher Fetcher, watcher Watcher) *Store {
	return NewNamedStore("", fetcher, watcher)
}

// NewNamedStore 创建带名称的 Store（方便调试）
func NewNamedStore(name string, fetcher Fetcher, watcher Watcher) *Store {
	if watcher == nil {
		watcher = NopWatcher{}
	}
	return &Store{
		name:    name,
		fetcher: fetcher,
		watcher: watcher,
		cache:   make(map[string][][]byte),
	}
}

// OneOfKey 获取单个密钥（第一个）
func (s *Store) OneOfKey(ctx context.Context, id string) ([]byte, error) {
	keys, err := s.AllOfKey(ctx, id)
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, ErrNotFound
	}
	return keys[0], nil
}

// AllOfKey 获取所有密钥
func (s *Store) AllOfKey(ctx context.Context, id string) ([][]byte, error) {
	s.mu.RLock()
	keys, ok := s.cache[id]
	s.mu.RUnlock()

	if ok {
		return keys, nil
	}

	return s.load(ctx, id)
}

// Subscribe 订阅密钥变更（实现 Subscribable 接口）
func (s *Store) Subscribe(id string, callback func(keys [][]byte)) {
	s.watcher.Subscribe(id, callback)
}

func (s *Store) load(ctx context.Context, id string) ([][]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// double check
	if keys, ok := s.cache[id]; ok {
		return keys, nil
	}

	keys, err := s.fetcher.Fetch(ctx, id)
	if err != nil {
		return nil, err
	}

	for i, k := range keys {
		logger.Debugf("[KeyStore:%s] load id=%s, key[%d] len=%d, salt_hex=%x", s.name, id, i, len(k), k[:min(16, len(k))])
	}

	s.cache[id] = keys

	// 通知订阅者
	s.watcher.Notify(id, keys)

	return keys, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
