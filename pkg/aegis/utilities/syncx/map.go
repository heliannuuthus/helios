// Package syncx 提供标准库 sync 包的泛型扩展。
package syncx

import "sync"

// Map 是 sync.Map 的泛型封装，消除所有类型断言。
type Map[K comparable, V any] struct {
	inner sync.Map
}

// Load 返回 key 对应的值，不存在返回零值和 false。
func (m *Map[K, V]) Load(key K) (V, bool) {
	v, ok := m.inner.Load(key)
	if !ok {
		var zero V
		return zero, false
	}
	return cast[V](v), true
}

// Store 设置 key 对应的值。
func (m *Map[K, V]) Store(key K, value V) {
	m.inner.Store(key, value)
}

// LoadOrStore 返回已有值或存入新值，loaded 表示是否为已有。
func (m *Map[K, V]) LoadOrStore(key K, value V) (actual V, loaded bool) {
	v, loaded := m.inner.LoadOrStore(key, value)
	return cast[V](v), loaded
}

// LoadAndDelete 返回并删除 key，不存在返回零值和 false。
func (m *Map[K, V]) LoadAndDelete(key K) (V, bool) {
	v, loaded := m.inner.LoadAndDelete(key)
	if !loaded {
		var zero V
		return zero, false
	}
	return cast[V](v), true
}

// Delete 删除 key。
func (m *Map[K, V]) Delete(key K) {
	m.inner.Delete(key)
}

// Range 遍历所有键值对，fn 返回 false 时停止。
func (m *Map[K, V]) Range(fn func(key K, value V) bool) {
	m.inner.Range(func(k, v any) bool {
		return fn(cast[K](k), cast[V](v))
	})
}

// Swap 设置 key 并返回旧值（如有）。
func (m *Map[K, V]) Swap(key K, value V) (previous V, loaded bool) {
	v, loaded := m.inner.Swap(key, value)
	if !loaded {
		var zero V
		return zero, false
	}
	return cast[V](v), true
}

// CompareAndSwap 仅在当前值等于 old 时替换为 new。
func (m *Map[K, V]) CompareAndSwap(key K, old, new V) (swapped bool) {
	return m.inner.CompareAndSwap(key, old, new)
}

// CompareAndDelete 仅在当前值等于 old 时删除。
func (m *Map[K, V]) CompareAndDelete(key K, old V) (deleted bool) {
	return m.inner.CompareAndDelete(key, old)
}

// Clear 删除所有键值对。
func (m *Map[K, V]) Clear() {
	m.inner.Clear()
}

func cast[T any](v any) T {
	t, _ := v.(T) //nolint:errcheck // type is guaranteed by Map's generic contract
	return t
}
