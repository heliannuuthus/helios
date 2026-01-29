package idp

import (
	"context"
	"sync"

	"github.com/heliannuuthus/helios/internal/auth/types"
)

// Provider IDP 提供者接口
type Provider interface {
	// Type 返回 IDP 类型标识
	Type() string

	// Exchange 用授权码换取用户信息
	// params: 通用参数，通常第一个是 code
	Exchange(ctx context.Context, params ...any) (*ExchangeResult, error)

	// FetchAdditionalInfo 补充获取用户信息（手机号、邮箱等）
	// infoType: "phone", "email", "realname" 等
	// params: 通用参数，不同 IDP 需要不同参数
	FetchAdditionalInfo(ctx context.Context, infoType string, params ...any) (*AdditionalInfo, error)

	// ToPublicConfig 转换为前端可用的公开配置（不含密钥）
	ToPublicConfig() *types.ConnectionConfig
}

// ExchangeResult 换取结果
type ExchangeResult struct {
	ProviderID string // IDP 侧用户唯一标识（openid）
	UnionID    string // 联合 ID（可选）
	RawData    string // 原始响应 JSON
}

// AdditionalInfo 补充信息结果
type AdditionalInfo struct {
	Type  string         `json:"type"`            // "phone", "email" 等
	Value string         `json:"value"`           // 具体值
	Extra map[string]any `json:"extra,omitempty"` // 额外数据
}

// Registry Provider 注册表
type Registry struct {
	mu        sync.RWMutex
	providers map[string]Provider
}

// NewRegistry 创建注册表
func NewRegistry() *Registry {
	return &Registry{
		providers: make(map[string]Provider),
	}
}

// Register 注册 Provider
func (r *Registry) Register(p Provider) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.providers[p.Type()] = p
}

// Get 获取 Provider
func (r *Registry) Get(idpType string) (Provider, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.providers[idpType]
	return p, ok
}

// List 列出所有已注册的 IDP 类型
func (r *Registry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	types := make([]string, 0, len(r.providers))
	for t := range r.providers {
		types = append(types, t)
	}
	return types
}

// Has 检查是否已注册指定类型的 Provider
func (r *Registry) Has(idpType string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.providers[idpType]
	return ok
}
