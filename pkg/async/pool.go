package async

import (
	"context"

	"github.com/heliannuuthus/helios/pkg/logger"
	"github.com/panjf2000/ants/v2"
)

// Pool 异步任务池，封装 ants goroutine pool
// 用于提交 fire-and-forget 的后台任务（如清理过期 token、更新登录时间等）
type Pool struct {
	pool *ants.Pool
}

// NewPool 创建异步任务池
// size: 最大并发 goroutine 数量
func NewPool(size int) (*Pool, error) {
	p, err := ants.NewPool(size, ants.WithPanicHandler(func(v any) {
		logger.Errorf("[AsyncPool] goroutine panic: %v", v)
	}))
	if err != nil {
		return nil, err
	}
	return &Pool{pool: p}, nil
}

// Go 提交异步任务（fire-and-forget）
// ctx 用于传递 trace 信息，任务内应使用独立的 context 控制超时
func (p *Pool) Go(fn func()) {
	if err := p.pool.Submit(fn); err != nil {
		logger.Warnf("[AsyncPool] submit task failed: %v", err)
	}
}

// GoWithContext 提交带 context 的异步任务
// 从原始 ctx 中提取需要的信息，但任务使用独立的 background context
func (p *Pool) GoWithContext(ctx context.Context, fn func(ctx context.Context)) {
	_ = ctx // 保留用于未来提取 trace/span 信息
	p.Go(func() {
		fn(context.Background())
	})
}

// Release 释放池资源（应用退出时调用）
func (p *Pool) Release() {
	p.pool.Release()
}
