// Package accessctl 提供基于 throttle 的访问控制管理器。
//
// 两种能力：
//   - 频率限流（ProbeRate）：控制请求速率，使用 Policy.Limits
//   - 验证计数（Strike）：记录一次验证失败并根据计数决定是否限流
package accessctl

import (
	"context"
	"time"

	"github.com/heliannuuthus/helios/pkg/logger"
	"github.com/heliannuuthus/helios/pkg/throttle"
)

// ACAction 访问控制决策
type ACAction int

const (
	ACAllowed     ACAction = iota // 放行
	ACRateLimited                 // 触发限流
)

// Policy 访问控制策略
// ProbeRate 使用 Key + Limits；Strike 使用 Key + Window + Threshold
type Policy struct {
	Key       string         // 维度 key
	Limits    map[string]int // 频率限流：窗口 → 上限，如 {"1m": 1, "24h": 10}
	Window    time.Duration  // 验证计数：统计窗口
	Threshold int            // 验证计数：达到此次数触发限流（0 = 始终限流）
}

// NewPolicy 创建 Policy 并设置维度 key
func NewPolicy(key string) *Policy {
	return &Policy{Key: key}
}

// RateLimits 设置频率限流窗口（用于 ProbeRate）
func (p *Policy) RateLimits(limits map[string]int) *Policy {
	p.Limits = limits
	return p
}

// FailWindow 设置验证计数统计窗口（用于 Strike）
func (p *Policy) FailWindow(window time.Duration) *Policy {
	p.Window = window
	return p
}

// ThrottleAt 设置触发限流的验证失败次数阈值（0 = 始终限流）
func (p *Policy) ThrottleAt(threshold int) *Policy {
	p.Threshold = threshold
	return p
}

// ==================== Manager ====================

// Manager 访问控制管理器
// 底层依赖 throttle.Throttler，提供频率限流和验证计数两种能力
type Manager struct {
	throttler *throttle.Throttler
}

// NewManager 创建访问控制管理器
func NewManager(t *throttle.Throttler) *Manager {
	return &Manager{throttler: t}
}

// ProbeRate 检查频率限流（AND 语义：全部通过才放行）
// 使用 Policy.Key + Policy.Limits
// 返回 0 表示放行，>0 为需要等待的秒数
func (m *Manager) ProbeRate(ctx context.Context, policies ...*Policy) int {
	if m == nil || m.throttler == nil || len(policies) == 0 {
		return 0
	}

	valid := make([]*Policy, 0, len(policies))
	for _, p := range policies {
		if p != nil && p.Key != "" && len(p.Limits) > 0 {
			valid = append(valid, p)
		}
	}
	if len(valid) == 0 {
		return 0
	}

	// Peek 全部策略（只读）
	for _, p := range valid {
		r, err := m.throttler.Peek(ctx, p.Key, p.Limits)
		if err != nil {
			logger.Warnf("[AccessCtl] ProbeRate Peek error for key %s: %v", p.Key, err)
			continue
		}
		if !r.Allowed {
			return r.RetryAfter
		}
	}

	// 全部通过，逐个 Allow 写入
	for _, p := range valid {
		r, err := m.throttler.Allow(ctx, p.Key, p.Limits)
		if err != nil {
			logger.Warnf("[AccessCtl] ProbeRate Allow error for key %s: %v", p.Key, err)
			continue
		}
		if !r.Allowed {
			return r.RetryAfter
		}
	}

	return 0
}

// Strike 记录一次验证失败并根据当前计数返回限流决策
// 认证失败后调用，达到阈值时返回 ACRateLimited + retryAfter 秒数
// 使用 Policy.Key + Policy.Window + Policy.Threshold
func (m *Manager) Strike(ctx context.Context, policy *Policy) (ACAction, int) {
	if m == nil || m.throttler == nil || policy == nil {
		return ACAllowed, 0
	}

	retryAfter := int(policy.Window.Seconds())

	if policy.Threshold == 0 {
		return ACRateLimited, retryAfter
	}

	count, err := m.throttler.Record(ctx, policy.Key, policy.Window)
	if err != nil {
		logger.Warnf("[AccessCtl] Strike Record error for key %s: %v", policy.Key, err)
		return ACAllowed, 0
	}

	if policy.Threshold > 0 && count >= int64(policy.Threshold) {
		return ACRateLimited, retryAfter
	}
	return ACAllowed, 0
}
