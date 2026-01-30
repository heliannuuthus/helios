// Package captcha provides captcha verification implementations.
package captcha

import (
	"context"
)

// Verifier 人机验证接口
type Verifier interface {
	// Verify 验证 captcha token
	// token: 前端获取的 captcha token
	// remoteIP: 用户 IP 地址（可选）
	Verify(ctx context.Context, token, remoteIP string) (bool, error)

	// GetSiteKey 获取站点密钥（前端使用）
	GetSiteKey() string

	// GetProvider 获取提供商名称
	GetProvider() string
}

// VerifyResult 验证结果
type VerifyResult struct {
	Success     bool     `json:"success"`
	ChallengeTS string   `json:"challenge_ts,omitempty"`
	Hostname    string   `json:"hostname,omitempty"`
	ErrorCodes  []string `json:"error-codes,omitempty"`
}
