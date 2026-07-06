package key

import "sync"

type watcher struct {
	mu        sync.RWMutex
	callbacks map[string][]func(keys [][]byte)
}

func newWatcher() watcher {
	return watcher{
		callbacks: make(map[string][]func(keys [][]byte)),
	}
}

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
