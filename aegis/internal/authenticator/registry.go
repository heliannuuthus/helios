// Package authenticator provides unified authenticator registry for all connection types.
package authenticator

import (
	"context"
	"sync"

	"github.com/heliannuuthus/helios/aegis/internal/types"
	"github.com/heliannuuthus/helios/hermes/models"
)

// Authenticator 统一认证器接口
// 所有认证方式（IDP、VChan、Factor）都实现此接口
type Authenticator interface {
	// Type 返回认证器类型标识（github, google, captcha, email_otp, totp...）
	Type() string

	// ConnectionType 返回连接类型（idp / vchan / factor）
	ConnectionType() types.ConnectionType

	// Prepare 返回该认证器的完整配置（含 Type，用于构建 ConnectionMap）
	Prepare() *types.ConnectionConfig

	// Authenticate 执行认证
	// flow: 认证流程上下文（包含当前 Connection、ConnectionMap 等）
	// params: 认证参数（proof、principal、strategy 等，由各实现自行解析）
	// 返回: (是否成功, 错误)
	// 认证器内部负责更新 flow 的副作用（如 Identities、Verified 等）
	Authenticate(ctx context.Context, flow *types.AuthFlow, params ...any) (bool, error)
}

// ChallengeVerifier 两阶段 Challenge 验证能力接口
// 由 FactorAuthenticator 和 VChanAuthenticator 实现
// Challenge Service 通过类型断言 authenticator.(ChallengeVerifier) 发现此能力
type ChallengeVerifier interface {
	// Initiate 启动 Challenge（执行副作用：发邮件、发短信等）
	// 限流冷却时间写入 challenge.RetryAfter
	Initiate(ctx context.Context, challenge *types.Challenge) error

	// Verify 验证 Challenge proof
	Verify(ctx context.Context, challenge *types.Challenge, proof string) (bool, error)
}

// IdentityResolver 身份解析能力接口
// IDP Authenticator 可实现此接口，允许 delegate 验证成功后通过 principal 查找用户信息
type IdentityResolver interface {
	Resolve(ctx context.Context, principal string) (*models.TUserInfo, error)
}

// Exchanger 一步交换能力接口（用于 Exchange 类型的 ChannelType）
// 如微信小程序 code 换手机号，支付宝小程序 code 换手机号
// Challenge Service 通过类型断言 authenticator.(Exchanger) 发现此能力
type Exchanger interface {
	// Exchange 用平台授权码换取 principal（如手机号）
	Exchange(ctx context.Context, code string) (principal string, err error)
}

// Registry 全局认证器注册表
// 统一管理所有 Connection 类型：IDP、VChan、MFA
type Registry struct {
	mu             sync.RWMutex
	authenticators map[string]Authenticator
}

// 全局 Registry 实例
var globalRegistry *Registry

// GlobalRegistry 获取全局 Registry 实例
func GlobalRegistry() *Registry {
	return globalRegistry
}

// NewRegistry 创建并设置全局注册表
func NewRegistry() *Registry {
	r := &Registry{
		authenticators: make(map[string]Authenticator),
	}
	globalRegistry = r
	return r
}

// ==================== Authenticator 注册与查询 ====================

// Register 注册 Authenticator
func (r *Registry) Register(a Authenticator) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.authenticators[a.Type()] = a
}

// Get 获取 Authenticator
func (r *Registry) Get(connection string) (Authenticator, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	a, ok := r.authenticators[connection]
	return a, ok
}

// Has 检查是否已注册指定的 Authenticator
func (r *Registry) Has(connection string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.authenticators[connection]
	return ok
}

// List 列出所有已注册的 Authenticator 类型
func (r *Registry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]string, 0, len(r.authenticators))
	for t := range r.authenticators {
		result = append(result, t)
	}
	return result
}

// All 返回所有已注册的 Authenticator
func (r *Registry) All() []Authenticator {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]Authenticator, 0, len(r.authenticators))
	for _, a := range r.authenticators {
		result = append(result, a)
	}
	return result
}

// Supports 检查是否支持指定的 connection 类型
func (r *Registry) Supports(connection string) bool {
	return r.Has(connection)
}

// Summary 返回注册表摘要信息
func (r *Registry) Summary() map[string]any {
	r.mu.RLock()
	defer r.mu.RUnlock()

	all := make([]string, 0, len(r.authenticators))
	for t := range r.authenticators {
		all = append(all, t)
	}

	return map[string]any{
		"authenticators": all,
		"count":          len(r.authenticators),
	}
}
