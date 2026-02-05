package keys

import (
	"time"

	"aidanwoods.dev/go-paseto"
)

// RefreshThreshold 刷新阈值，剩余时间小于总时间的 20% 时触发异步刷新
const RefreshThreshold = 0.2

// KeyEntry 公钥缓存条目
type KeyEntry struct {
	Key       paseto.V4AsymmetricPublicKey
	ExpiresAt time.Time
	FetchedAt time.Time
}

// IsExpired 检查是否过期
func (e *KeyEntry) IsExpired() bool {
	return time.Now().After(e.ExpiresAt)
}

// NeedsRefresh 检查是否需要异步刷新（剩余时间小于阈值）
func (e *KeyEntry) NeedsRefresh() bool {
	remaining := time.Until(e.ExpiresAt)
	total := e.ExpiresAt.Sub(e.FetchedAt)
	if total <= 0 {
		return true
	}
	return remaining < time.Duration(float64(total)*RefreshThreshold)
}
