// Package captcha provides captcha verification implementations.
package captcha

import (
	"context"
)

// Verifier 人机验证接口
type Verifier interface {
	// Verify 验证凭证
	// proof: 验证凭证（captcha token）
	// remoteIP: 用户 IP 地址（可选）
	Verify(ctx context.Context, proof, remoteIP string) (bool, error)

	// GetIdentifier 获取标识符（如 site key）
	GetIdentifier() string

	// GetProvider 获取提供商名称（如 turnstile）
	GetProvider() string
}
