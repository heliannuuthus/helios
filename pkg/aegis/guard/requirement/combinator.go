package requirement

import (
	"context"

	"golang.org/x/sync/errgroup"

	"github.com/heliannuuthus/pkg/aegis/guard"
	"github.com/heliannuuthus/pkg/aegis/utilities/errors"
)

type anyOfRequirement struct {
	reqs []guard.Requirement
}

// AnyOf 任一 Requirement 满足即通过。
// 并发执行所有 Requirement，任一成功即 cancel 剩余。
func AnyOf(reqs ...guard.Requirement) guard.Requirement {
	if len(reqs) == 0 {
		panic("AnyOf requires at least one requirement")
	}
	return &anyOfRequirement{reqs: reqs}
}

func (r *anyOfRequirement) Enforce(ctx context.Context) error {
	if len(r.reqs) == 1 {
		return r.reqs[0].Enforce(ctx)
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type result struct{ err error }
	ch := make(chan result, len(r.reqs))

	for _, req := range r.reqs {
		go func(req guard.Requirement) {
			ch <- result{err: req.Enforce(ctx)}
		}(req)
	}

	var lastErr error
	for range r.reqs {
		res := <-ch
		if res.err == nil {
			return nil
		}
		lastErr = res.err
	}
	return lastErr
}

type allOfRequirement struct {
	reqs []guard.Requirement
}

// AllOf 所有 Requirement 均满足才通过。
// errgroup 并发执行，任一失败即 cancel 剩余。
func AllOf(reqs ...guard.Requirement) guard.Requirement {
	if len(reqs) == 0 {
		panic("AllOf requires at least one requirement")
	}
	return &allOfRequirement{reqs: reqs}
}

func (r *allOfRequirement) Enforce(ctx context.Context) error {
	if len(r.reqs) == 1 {
		return r.reqs[0].Enforce(ctx)
	}

	g, ctx := errgroup.WithContext(ctx)
	for _, req := range r.reqs {
		g.Go(func() error {
			return req.Enforce(ctx)
		})
	}
	return g.Wait()
}

type notRequirement struct {
	req guard.Requirement
}

// Not 取反：内部 Requirement 失败则通过，通过则返回 Forbidden。
func Not(req guard.Requirement) guard.Requirement {
	return &notRequirement{req: req}
}

func (r *notRequirement) Enforce(ctx context.Context) error {
	if err := r.req.Enforce(ctx); err != nil {
		return nil
	}
	return errors.ErrForbidden
}
