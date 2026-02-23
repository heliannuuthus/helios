package key

import (
	"sync"
)

// Subscribable 支持订阅密钥变更
type Subscribable interface {
	Subscribe(id string, callback func(keys [][]byte))
}

// Notifiable 支持通知密钥变更
type Notifiable interface {
	Notify(id string, keys [][]byte)
}

// Watcher 组合接口（同时支持订阅和通知）
type Watcher interface {
	Subscribable
	Notifiable
}

// trySubscribe 尝试订阅密钥变更（如果 provider 支持）
func trySubscribe(provider Provider, id string, callback func(keys [][]byte)) {
	if sub, ok := provider.(Subscribable); ok {
		sub.Subscribe(id, callback)
	}
}

// SimpleWatcher 简单的 Watcher 实现（异步通知）
type SimpleWatcher struct {
	mu        sync.RWMutex
	callbacks map[string][]func(keys [][]byte)
}

// NewSimpleWatcher 创建 SimpleWatcher
func NewSimpleWatcher() *SimpleWatcher {
	return &SimpleWatcher{
		callbacks: make(map[string][]func(keys [][]byte)),
	}
}

// Subscribe 订阅密钥变更
func (w *SimpleWatcher) Subscribe(id string, callback func(keys [][]byte)) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.callbacks[id] = append(w.callbacks[id], callback)
}

// Notify 异步通知密钥变更
func (w *SimpleWatcher) Notify(id string, keys [][]byte) {
	w.mu.RLock()
	callbacks := w.callbacks[id]
	w.mu.RUnlock()

	for _, cb := range callbacks {
		go cb(keys)
	}
}

// NopWatcher 空实现，不做任何事
type NopWatcher struct{}

// Subscribe 空实现
func (NopWatcher) Subscribe(_ string, _ func(keys [][]byte)) {}

// Notify 空实现
func (NopWatcher) Notify(_ string, _ [][]byte) {}
