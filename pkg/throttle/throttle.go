// Package throttle 提供基于 Redis Sorted Set 的滑动窗口节流器。
//
// 核心思路：每个限流维度使用一个 Sorted Set，所有时间窗口共享同一个 key。
// member 为唯一标识（时间戳+随机后缀），score 为事件发生时间（毫秒）。
// 多窗口检查通过一次 Lua 脚本完成：先清理最大窗口外的过期记录，
// 再对每个窗口用 ZCOUNT 统计范围内的记录数。
package throttle

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/heliannuuthus/helios/pkg/helpers"
	"github.com/heliannuuthus/helios/pkg/redis"
)

// peekScript 多窗口只读检查（不写入）
//
// KEYS[1] = 限流 key
// ARGV[1] = 当前时间（毫秒）
// ARGV[2] = 窗口数量 N
// ARGV[3..3+N-1]   = 各窗口的 window_start（毫秒），按窗口从大到小排列
// ARGV[3+N..3+2N-1] = 各窗口的 limit
//
// 返回: {allowed(0/1), rejected_window_index(-1=全通过), oldest_score}
const peekScript = `
local key = KEYS[1]
local now = tonumber(ARGV[1])
local n = tonumber(ARGV[2])

local window_starts = {}
local limits = {}
for i = 1, n do
    window_starts[i] = tonumber(ARGV[2 + i])
    limits[i] = tonumber(ARGV[2 + n + i])
end

-- 清理最大窗口外的过期记录
redis.call('ZREMRANGEBYSCORE', key, '-inf', window_starts[1])

-- 逐窗口检查（只读）
for i = 1, n do
    local count = redis.call('ZCOUNT', key, window_starts[i], '+inf')
    if count >= limits[i] then
        local oldest = redis.call('ZRANGEBYSCORE', key, window_starts[i], '+inf', 'WITHSCORES', 'LIMIT', 0, 1)
        local oldest_score = 0
        if #oldest >= 2 then
            oldest_score = tonumber(oldest[2])
        end
        return {0, i, oldest_score}
    end
end

return {1, -1, 0}
`

// allowScript 多窗口检查并写入（原子操作）
//
// KEYS[1] = 限流 key
// ARGV[1] = 当前时间（毫秒）
// ARGV[2] = member（唯一标识）
// ARGV[3] = 窗口数量 N
// ARGV[4..4+N-1]   = 各窗口的 window_start（毫秒），按窗口从大到小排列
// ARGV[4+N..4+2N-1] = 各窗口的 limit
// ARGV[4+2N] = TTL（秒），取最大窗口 + 1
//
// 返回: {allowed(0/1), rejected_window_index(-1=全通过), oldest_score}
const allowScript = `
local key = KEYS[1]
local now = tonumber(ARGV[1])
local member = ARGV[2]
local n = tonumber(ARGV[3])

local window_starts = {}
local limits = {}
for i = 1, n do
    window_starts[i] = tonumber(ARGV[3 + i])
    limits[i] = tonumber(ARGV[3 + n + i])
end
local ttl = tonumber(ARGV[4 + 2 * n])

-- 清理最大窗口外的过期记录
redis.call('ZREMRANGEBYSCORE', key, '-inf', window_starts[1])

-- 逐窗口检查
for i = 1, n do
    local count = redis.call('ZCOUNT', key, window_starts[i], '+inf')
    if count >= limits[i] then
        local oldest = redis.call('ZRANGEBYSCORE', key, window_starts[i], '+inf', 'WITHSCORES', 'LIMIT', 0, 1)
        local oldest_score = 0
        if #oldest >= 2 then
            oldest_score = tonumber(oldest[2])
        end
        return {0, i, oldest_score}
    end
end

-- 全部通过，写入记录
redis.call('ZADD', key, now, member)
redis.call('EXPIRE', key, ttl)
return {1, -1, 0}
`

// countScript 只读统计指定窗口内的记录数（不写入）
const countScript = `
local key = KEYS[1]
local window_start = tonumber(ARGV[1])

redis.call('ZREMRANGEBYSCORE', key, '-inf', window_start)
return redis.call('ZCARD', key)
`

// recordScript 仅记录一次事件并返回指定窗口内计数
const recordScript = `
local key = KEYS[1]
local window_start = tonumber(ARGV[1])
local now = tonumber(ARGV[2])
local member = ARGV[3]
local ttl = tonumber(ARGV[4])

redis.call('ZREMRANGEBYSCORE', key, '-inf', window_start)
redis.call('ZADD', key, now, member)
redis.call('EXPIRE', key, ttl)
return redis.call('ZCARD', key)
`

// Throttler 基于 Redis Sorted Set 的滑动窗口节流器
type Throttler struct {
	redis redis.Client
}

// NewThrottler 创建节流器
func NewThrottler(redis redis.Client) *Throttler {
	return &Throttler{redis: redis}
}

// Result 节流检查结果
type Result struct {
	Allowed    bool
	RetryAfter int // 被限流时，距离可重试的秒数
}

// windowLimit 内部结构：解析后的窗口配置
type windowLimit struct {
	window time.Duration
	limit  int
}

// Peek 多窗口只读检查（不写入记录）
// 用于多维度场景：先 Peek 所有维度确认全部通过后，再对每个维度调用 Allow 写入。
// 避免维度 A 通过并写入、维度 B 被拒时，维度 A 多计了一条无效记录。
func (t *Throttler) Peek(ctx context.Context, key string, limits map[string]int) (*Result, error) {
	if len(limits) == 0 {
		return &Result{Allowed: true}, nil
	}

	windows, err := parseAndSortWindows(limits)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	nowMs := now.UnixMilli()

	n := len(windows)
	args := make([]any, 0, 2+2*n)
	args = append(args, nowMs, n)

	for _, w := range windows {
		windowStartMs := now.Add(-w.window).UnixMilli()
		args = append(args, windowStartMs)
	}
	for _, w := range windows {
		args = append(args, w.limit)
	}

	result, err := t.redis.Eval(ctx, peekScript, []string{key}, args...)
	if err != nil {
		return nil, fmt.Errorf("throttle peek failed: %w", err)
	}

	vals, ok := result.([]interface{})
	if !ok || len(vals) < 3 {
		return nil, fmt.Errorf("unexpected throttle peek result: %v", result)
	}

	allowed := toInt64(vals[0]) == 1
	rejectedIdx := toInt64(vals[1])
	oldestMs := toInt64(vals[2])

	r := &Result{Allowed: allowed}

	if !allowed && rejectedIdx > 0 && int(rejectedIdx) <= n {
		w := windows[rejectedIdx-1]
		if oldestMs > 0 {
			elapsed := nowMs - oldestMs
			remaining := w.window.Milliseconds() - elapsed
			if remaining > 0 {
				r.RetryAfter = int(remaining/1000) + 1
			}
		}
	}

	return r, nil
}

// Allow 多窗口检查并写入（如 {"1m": 1, "1h": 10, "24h": 20}）
// 单个 key，单次 Lua 调用，检查所有窗口。通过则写入一条记录，被拒则不写入。
// 注意：单维度使用时直接调用即可；多维度场景请先 Peek 全部维度，再逐维度 Allow。
func (t *Throttler) Allow(ctx context.Context, key string, limits map[string]int) (*Result, error) {
	if len(limits) == 0 {
		return &Result{Allowed: true}, nil
	}

	// 解析并按窗口从大到小排列（大窗口的 window_start 最小）
	windows, err := parseAndSortWindows(limits)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	nowMs := now.UnixMilli()
	member := fmt.Sprintf("%d:%s", nowMs, helpers.GenerateID(8))

	// 构建 Lua ARGV
	n := len(windows)
	args := make([]any, 0, 3+2*n+1)
	args = append(args, nowMs, member, n)

	for _, w := range windows {
		windowStartMs := now.Add(-w.window).UnixMilli()
		args = append(args, windowStartMs)
	}
	for _, w := range windows {
		args = append(args, w.limit)
	}

	// TTL = 最大窗口 + 1s
	maxWindow := windows[0].window
	ttlSec := int64(maxWindow.Seconds()) + 1
	args = append(args, ttlSec)

	result, err := t.redis.Eval(ctx, allowScript, []string{key}, args...)
	if err != nil {
		return nil, fmt.Errorf("throttle check failed: %w", err)
	}

	vals, ok := result.([]interface{})
	if !ok || len(vals) < 3 {
		return nil, fmt.Errorf("unexpected throttle result: %v", result)
	}

	allowed := toInt64(vals[0]) == 1
	rejectedIdx := toInt64(vals[1])
	oldestMs := toInt64(vals[2])

	r := &Result{Allowed: allowed}

	if !allowed && rejectedIdx > 0 && int(rejectedIdx) <= n {
		w := windows[rejectedIdx-1]
		if oldestMs > 0 {
			elapsed := nowMs - oldestMs
			remaining := w.window.Milliseconds() - elapsed
			if remaining > 0 {
				r.RetryAfter = int(remaining/1000) + 1
			}
		}
	}

	return r, nil
}

// Count 只读统计指定窗口内的记录数（不写入）
func (t *Throttler) Count(ctx context.Context, key string, window time.Duration) (int64, error) {
	windowStartMs := time.Now().Add(-window).UnixMilli()

	result, err := t.redis.Eval(ctx, countScript,
		[]string{key},
		windowStartMs,
	)
	if err != nil {
		return 0, fmt.Errorf("throttle count failed: %w", err)
	}

	return toInt64(result), nil
}

// Record 记录一次事件，返回指定窗口内的总次数
func (t *Throttler) Record(ctx context.Context, key string, window time.Duration) (int64, error) {
	now := time.Now()
	nowMs := now.UnixMilli()
	windowStartMs := now.Add(-window).UnixMilli()
	member := fmt.Sprintf("%d:%s", nowMs, helpers.GenerateID(8))
	ttlSec := int64(window.Seconds()) + 1

	result, err := t.redis.Eval(ctx, recordScript,
		[]string{key},
		windowStartMs, nowMs, member, ttlSec,
	)
	if err != nil {
		return 0, fmt.Errorf("throttle record failed: %w", err)
	}

	return toInt64(result), nil
}

// ==================== 辅助函数 ====================

// parseAndSortWindows 解析限流配置并按窗口从大到小排序
func parseAndSortWindows(limits map[string]int) ([]windowLimit, error) {
	windows := make([]windowLimit, 0, len(limits))
	for raw, limit := range limits {
		d, err := parseDuration(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid window %q: %w", raw, err)
		}
		windows = append(windows, windowLimit{window: d, limit: limit})
	}
	sort.Slice(windows, func(i, j int) bool {
		return windows[i].window > windows[j].window
	})
	return windows, nil
}

// parseDuration 解析限流窗口字符串（支持 "1m", "1h", "24h", "1d" 等）
func parseDuration(s string) (time.Duration, error) {
	if d, err := time.ParseDuration(s); err == nil {
		return d, nil
	}
	if len(s) > 1 && s[len(s)-1] == 'd' {
		if d, err := time.ParseDuration(s[:len(s)-1] + "h"); err == nil {
			return d * 24, nil
		}
	}
	return 0, fmt.Errorf("unsupported duration format: %s", s)
}

// toInt64 将 Lua 返回值转换为 int64
func toInt64(v interface{}) int64 {
	switch n := v.(type) {
	case int64:
		return n
	case int:
		return int64(n)
	case float64:
		return int64(n)
	default:
		return 0
	}
}
