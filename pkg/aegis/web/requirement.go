package web

import "context"

// Requirement 声明式鉴权条件接口。
// Guard 在 Check 阶段依次调用 Enforce，全部通过才放行。
type Requirement interface {
	Enforce(ctx context.Context) error
}
