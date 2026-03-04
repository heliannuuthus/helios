package key

import "sync"

// watcher 订阅通知组件，密钥变更时触发回调
type watcher struct {
	mu        sync.RWMutex
	callbacks map[string][]func(keys [][]byte)
}

func newWatcher() watcher {
	return watcher{
		callbacks: make(map[string][]func(keys [][]byte)),
	}
}

// Subscribe 订阅密钥变更
func (w *watcher) Subscribe(id string, callback func(keys [][]byte)) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.callbacks[id] = append(w.callbacks[id], callback)
}

func (w *watcher) notify(id string, keys [][]byte) {
	w.mu.RLock()
	cbs := make([]func(keys [][]byte), len(w.callbacks[id]))
	copy(cbs, w.callbacks[id])
	w.mu.RUnlock()

	for _, cb := range cbs {
		cb(keys)
	}
}
