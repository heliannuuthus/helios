// Package accessctl 提供基于 throttle 的访问控制管理器。
//
// 两种能力：
//   - 频率限流（ProbeRate）：控制请求速率，使用 Policy.Limits
//   - 验证计数（Strike）：记录一次验证尝试并根据计数返回决策
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
	ACAllowed ACAction = iota // 放行
	ACCaptcha                 // 需要 captcha（触发人机验证）
)

// Policy 访问控制策略
// ProbeRate 使用 Key + Limits；Strike 使用 Key + Window + CaptchaThreshold
type Policy struct {
	Key              string         // 维度 key
	Limits           map[string]int // 频率限流：窗口 → 上限，如 {"1m": 1, "24h": 10}
	Window           time.Duration  // 验证计数：统计窗口
	CaptchaThreshold int            // 验证计数：达到此次数要求 captcha（0 = 始终需要）
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

// CaptchaAt 设置触发 captcha 的验证次数阈值（0 = 始终需要）
func (p *Policy) CaptchaAt(threshold int) *Policy {
	p.CaptchaThreshold = threshold
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

// Strike 记录一次验证尝试并根据当前计数返回决策
// 每次调用 Authenticate 时前置执行，无论认证结果如何（频率限制语义）
// 使用 Policy.Key + Policy.Window + Policy.CaptchaThreshold
func (m *Manager) Strike(ctx context.Context, policy *Policy) ACAction {
	if m == nil || m.throttler == nil || policy == nil {
		return ACAllowed
	}

	if policy.CaptchaThreshold == 0 {
		return ACCaptcha
	}

	count, err := m.throttler.Record(ctx, policy.Key, policy.Window)
	if err != nil {
		logger.Warnf("[AccessCtl] Strike Record error for key %s: %v", policy.Key, err)
		return ACAllowed
	}

	if policy.CaptchaThreshold > 0 && count >= int64(policy.CaptchaThreshold) {
		return ACCaptcha
	}
	return ACAllowed
}
