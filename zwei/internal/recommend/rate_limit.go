package recommend

import (
	"sync"
	"time"
)

// DailyRateLimiter 每日推荐次数限制器
type DailyRateLimiter struct {
	mu       sync.RWMutex
	counts   map[string]*userCount
	maxDaily int
}

type userCount struct {
	count   int
	resetAt time.Time
}

// NewDailyRateLimiter 创建每日限流器
func NewDailyRateLimiter(maxDaily int) *DailyRateLimiter {
	limiter := &DailyRateLimiter{
		counts:   make(map[string]*userCount),
		maxDaily: maxDaily,
	}
	// 启动定时清理
	go limiter.cleanup()
	return limiter
}

// Check 检查用户是否超过每日限制
// 返回 (剩余次数, 是否允许)
func (l *DailyRateLimiter) Check(userID string) (remaining int, allowed bool) {
	if userID == "" {
		// 未登录用户不限制（或可以用 IP 限制）
		return l.maxDaily, true
	}

	l.mu.RLock()
	uc, exists := l.counts[userID]
	l.mu.RUnlock()

	now := time.Now()

	if !exists || now.After(uc.resetAt) {
		// 新用户或已过期，初始化
		return l.maxDaily, true
	}

	remaining = l.maxDaily - uc.count
	return remaining, remaining > 0
}

// Increment 增加用户推荐次数
func (l *DailyRateLimiter) Increment(userID string) {
	if userID == "" {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	tomorrow := today.Add(24 * time.Hour)

	uc, exists := l.counts[userID]
	if !exists || now.After(uc.resetAt) {
		l.counts[userID] = &userCount{
			count:   1,
			resetAt: tomorrow,
		}
		return
	}

	uc.count++
}

// GetRemaining 获取用户剩余次数
func (l *DailyRateLimiter) GetRemaining(userID string) int {
	if userID == "" {
		return l.maxDaily
	}

	l.mu.RLock()
	defer l.mu.RUnlock()

	uc, exists := l.counts[userID]
	if !exists {
		return l.maxDaily
	}

	now := time.Now()
	if now.After(uc.resetAt) {
		return l.maxDaily
	}

	remaining := l.maxDaily - uc.count
	if remaining < 0 {
		return 0
	}
	return remaining
}

// cleanup 定时清理过期记录（每小时执行）
func (l *DailyRateLimiter) cleanup() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		l.mu.Lock()
		now := time.Now()
		for userID, uc := range l.counts {
			if now.After(uc.resetAt) {
				delete(l.counts, userID)
			}
		}
		l.mu.Unlock()
	}
}
