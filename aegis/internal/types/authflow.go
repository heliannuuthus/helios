// Package types provides type definitions for the Auth module.
// nolint:revive // This package name follows Go conventions for internal type packages.
package types

import (
	"time"

	"github.com/go-json-experiment/json"

	"github.com/heliannuuthus/helios/hermes/models"
	"github.com/heliannuuthus/helios/pkg/binding"
	"github.com/heliannuuthus/helios/pkg/helpers"
)

// FlowState 认证流程状态
type FlowState string

const (
	FlowStateInitialized   FlowState = "initialized"   // 已初始化
	FlowStateAuthenticated FlowState = "authenticated" // 已认证（用户已验证）
	FlowStateAuthorized    FlowState = "authorized"    // 已授权（权限已计算）
	FlowStateCompleted     FlowState = "completed"     // 已完成（授权码已生成）
	FlowStateFailed        FlowState = "failed"        // 已失败（发生错误）
)

// Extra key 常量
const (
	ExtraKeyStrategy = "strategy"
)

// AuthFlow 认证流程上下文
// auth session = flowID
type AuthFlow struct {
	ID           string    `json:"id"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	MaxExpiresAt time.Time `json:"max_expires_at"` // 最大生命周期截止时间，超过后不可续期
	State        FlowState `json:"state"`

	// 请求参数
	Request *AuthRequest `json:"request"`

	// 实体信息（认证过程中填充）
	Application *models.ApplicationWithKey `json:"application,omitempty"`
	Service     *models.ServiceWithKey     `json:"service,omitempty"`
	User        *models.UserWithDecrypted  `json:"user,omitempty"`     // 系统中的已有用户（identify 匹配到的 / 认证完成后的）
	Identify    *models.TUserInfo          `json:"identify,omitempty"` // 当前 IDP 认证返回的身份信息（未绑定，用于 Account Linking 匹配）

	// Connection 配置
	ConnectionMap map[string]*ConnectionConfig `json:"connection_map,omitempty"` // 所有可用的 Connection 配置
	Connection    string                       `json:"connection,omitempty"`     // 当前正在验证的 Connection

	// 认证结果
	Identities models.Identities `json:"identities,omitempty"` // 用户全部身份绑定

	// 授权结果
	GrantedScopes []string `json:"granted_scopes,omitempty"`

	// 额外数据（不序列化，仅在当前请求生命周期内有效）
	Extra map[string]string `json:"-"`

	// 错误状态（发生错误时填充）
	Error *FlowError `json:"error,omitempty"`
}

// FlowError 流程错误信息
type FlowError struct {
	HTTPStatus  int            `json:"http_status"`
	Code        string         `json:"code"`
	Description string         `json:"description,omitempty"`
	Data        map[string]any `json:"data,omitempty"`
}

// AuthRequest 认证请求参数
type AuthRequest struct {
	// OAuth2 标准参数
	ResponseType        string                 `json:"response_type" form:"response_type" binding:"required,oneof=code"`
	ClientID            string                 `json:"client_id" form:"client_id" binding:"required"`
	Audience            string                 `json:"audience" form:"audience" binding:"required"`
	RedirectURI         string                 `json:"redirect_uri" form:"redirect_uri" binding:"required"`
	CodeChallenge       string                 `json:"code_challenge" form:"code_challenge" binding:"required"`
	CodeChallengeMethod string                 `json:"code_challenge_method" form:"code_challenge_method" binding:"required,oneof=S256"`
	State               string                 `json:"state,omitempty" form:"state"`
	Scope               binding.SpaceDelimited `json:"scope,omitempty" form:"scope"`

	// OIDC 扩展参数
	Prompt    binding.SpaceDelimited `json:"prompt,omitempty" form:"prompt"`         // none, login, consent
	Nonce     string                 `json:"nonce,omitempty" form:"nonce"`           // 防重放攻击
	LoginHint string                 `json:"login_hint,omitempty" form:"login_hint"` // 登录提示（邮箱/手机）

	// 其他扩展参数 - 序列化时平铺到顶层
	Params map[string]any `json:"-" form:"-"`
}

// authRequestAlias 用于避免 MarshalJSON/UnmarshalJSON 递归
type authRequestAlias AuthRequest

// 标准字段名集合，用于区分扩展参数
var authRequestKnownFields = map[string]bool{
	"response_type":         true,
	"client_id":             true,
	"audience":              true,
	"redirect_uri":          true,
	"code_challenge":        true,
	"code_challenge_method": true,
	"state":                 true,
	"scope":                 true,
	// OIDC 扩展参数
	"prompt":     true,
	"nonce":      true,
	"login_hint": true,
}

// Prompt 常量
const (
	PromptNone    = "none"    // 静默认证，如果未登录或未授权，返回错误
	PromptLogin   = "login"   // 强制重新登录（忽略现有 SSO 会话）
	PromptConsent = "consent" // 强制显示授权页面
)

// MarshalJSON 自定义序列化，将 Params 平铺到顶层
func (r AuthRequest) MarshalJSON() ([]byte, error) {
	// 先序列化标准字段
	alias := authRequestAlias(r)
	data, err := json.Marshal(alias)
	if err != nil {
		return nil, err
	}

	// 如果没有扩展参数，直接返回
	if len(r.Params) == 0 {
		return data, nil
	}

	// 解析为 map 以便合并
	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}

	// 合并扩展参数（平铺到顶层）
	for k, v := range r.Params {
		// 不覆盖标准字段
		if !authRequestKnownFields[k] {
			result[k] = v
		}
	}

	return json.Marshal(result)
}

// UnmarshalJSON 自定义反序列化，提取已知字段，剩余放入 Params
func (r *AuthRequest) UnmarshalJSON(data []byte) error {
	// 先解析标准字段
	var alias authRequestAlias
	if err := json.Unmarshal(data, &alias); err != nil {
		return err
	}
	*r = AuthRequest(alias)

	// 解析所有字段
	var allFields map[string]any
	if err := json.Unmarshal(data, &allFields); err != nil {
		return err
	}

	// 提取扩展参数（非标准字段）
	r.Params = make(map[string]any)
	for k, v := range allFields {
		if !authRequestKnownFields[k] {
			r.Params[k] = v
		}
	}

	// 如果没有扩展参数，设为 nil
	if len(r.Params) == 0 {
		r.Params = nil
	}

	return nil
}

// Get 获取扩展参数
func (r *AuthRequest) Get(key string) (any, bool) {
	if r.Params == nil {
		return nil, false
	}
	v, ok := r.Params[key]
	return v, ok
}

// GetString 获取字符串类型的扩展参数
func (r *AuthRequest) GetString(key string) string {
	v, ok := r.Get(key)
	if !ok {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// Set 设置扩展参数
func (r *AuthRequest) Set(key string, value any) {
	if r.Params == nil {
		r.Params = make(map[string]any)
	}
	r.Params[key] = value
}

// Connection 前端公开的连接信息（不含密钥和运行时状态）
type Connection struct {
	Type       ConnectionType `json:"type"`                // 连接类型（idp / vchan / factor）
	Connection string         `json:"connection"`          // 标识（github, google, wechat-mp, user, staff, email_otp, totp, captcha...）
	Identifier string         `json:"identifier,omitzero"` // 公开标识（client_id / site_key / rp_id）
	Strategy   []string       `json:"strategy,omitzero"`   // 认证方式（user/staff: password, webauthn; captcha: turnstile; 其余忽略）
	Delegate   []string       `json:"delegate,omitzero"`   // 可替代主认证的独立验证方式（totp, email_otp）
	Require    []string       `json:"require,omitzero"`    // 前置条件（captcha）
}

// NewConnection 从 ConnectionConfig 构造前端公开的 Connection
func NewConnection(cfg *ConnectionConfig) *Connection {
	return &Connection{
		Type:       cfg.Type,
		Connection: cfg.Connection,
		Identifier: cfg.Identifier,
		Strategy:   cfg.Strategy,
		Delegate:   cfg.Delegate,
		Require:    cfg.Require,
	}
}

// ConnectionConfig 后端内部完整配置（含私有密钥和运行时状态）
type ConnectionConfig struct {
	Type       ConnectionType `json:"type"`                // 连接类型（idp / vchan / factor）
	Connection string         `json:"connection"`          // 标识
	Secret     string         `json:"-"`                   // 私有密钥（不序列化到 Redis / API）
	Identifier string         `json:"identifier,omitzero"` // 公开标识（client_id / site_key / rp_id）
	Strategy   []string       `json:"strategy,omitzero"`   // 认证方式
	Delegate   []string       `json:"delegate,omitzero"`   // 可替代主认证的独立验证方式（如 email_otp, totp），与 Strategy 同级
	Require    []string       `json:"require,omitzero"`    // 前置条件
	Verified   bool           `json:"verified,omitempty"`  // 运行时：是否已通过验证
}

// ContainsStrategy 判断给定 strategy 是否在当前 connection 的 strategy 列表中
func (c *ConnectionConfig) ContainsStrategy(strategy string) bool {
	if strategy == "" || len(c.Strategy) == 0 {
		return false
	}
	for _, s := range c.Strategy {
		if s == strategy {
			return true
		}
	}
	return false
}

// ConnectionsMap API 响应：按 ConnectionType 分类
// JSON 示例: {"idp": [...], "vchan": [...], "factor": [...]}
type ConnectionsMap map[ConnectionType][]*Connection

// ==================== 辅助函数 ====================

// GenerateFlowID 生成 Flow ID（16位 Base62，约 62^16 ≈ 4.7×10^28 种可能）
func GenerateFlowID() string {
	return helpers.GenerateID(16)
}

// GenerateAuthorizationCode 生成授权码（32位 Base62，约 62^32 ≈ 2.3×10^57 种可能）
func GenerateAuthorizationCode() string {
	return helpers.GenerateID(32)
}

// NewAuthFlow 创建新的 AuthFlow
func NewAuthFlow(req *AuthRequest, ttl time.Duration, maxLifetime time.Duration) *AuthFlow {
	now := time.Now()
	return &AuthFlow{
		ID:           GenerateFlowID(),
		CreatedAt:    now,
		ExpiresAt:    now.Add(ttl),
		MaxExpiresAt: now.Add(maxLifetime),
		State:        FlowStateInitialized,
		Request:      req,
	}
}

// IsExpired 检查是否已过期（滑动窗口过期）
func (f *AuthFlow) IsExpired() bool {
	return time.Now().After(f.ExpiresAt)
}

// IsMaxExpired 检查是否超过最大生命周期
func (f *AuthFlow) IsMaxExpired() bool {
	return !f.MaxExpiresAt.IsZero() && time.Now().After(f.MaxExpiresAt)
}

// Renew 续期 AuthFlow（滑动窗口续期，不超过最大生命周期）
func (f *AuthFlow) Renew(ttl time.Duration) {
	now := time.Now()
	newExpiresAt := now.Add(ttl)
	// 不超过最大生命周期
	if !f.MaxExpiresAt.IsZero() && newExpiresAt.After(f.MaxExpiresAt) {
		newExpiresAt = f.MaxExpiresAt
	}
	f.ExpiresAt = newExpiresAt
}

// CanAuthenticate 检查是否可以进行认证
func (f *AuthFlow) CanAuthenticate() bool {
	return f.State == FlowStateInitialized && !f.IsExpired()
}

// SetConnectionMap 设置 ConnectionMap
func (f *AuthFlow) SetConnectionMap(connMap map[string]*ConnectionConfig) {
	f.ConnectionMap = connMap
}

// SetConnection 设置当前正在验证的 Connection
func (f *AuthFlow) SetConnection(connection string) {
	f.Connection = connection
}

// GetCurrentConnConfig 获取当前 Connection 的配置
func (f *AuthFlow) GetCurrentConnConfig() *ConnectionConfig {
	if f.Connection == "" || f.ConnectionMap == nil {
		return nil
	}
	return f.ConnectionMap[f.Connection]
}

// GetAvailableConnections 按 ConnectionType 分类返回可用的 Connection 列表
func (f *AuthFlow) GetAvailableConnections() ConnectionsMap {
	result := make(ConnectionsMap)
	if f.ConnectionMap == nil {
		return result
	}
	for _, cfg := range f.ConnectionMap {
		result[cfg.Type] = append(result[cfg.Type], NewConnection(cfg))
	}
	return result
}

// AddIdentity 添加已认证的身份绑定及 IDP 返回的身份信息
func (f *AuthFlow) AddIdentity(identity *models.UserIdentity, idpProfile *models.TUserInfo) {
	f.Identities = append(f.Identities, identity)
	if idpProfile != nil {
		f.Identify = idpProfile
	}
}

// GetIdentity 从已认证的身份中查找指定 connection 对应的身份
func (f *AuthFlow) GetIdentity(connection string) *models.UserIdentity {
	return f.Identities.FindByIDP(connection)
}

// SetAuthenticated 设置为已认证状态
func (f *AuthFlow) SetAuthenticated(user *models.UserWithDecrypted) {
	f.State = FlowStateAuthenticated
	f.User = user
}

// AllRequiredVerified 检查当前 Connection 的所有 Require 依赖是否已验证
func (f *AuthFlow) AllRequiredVerified() bool {
	connCfg := f.GetCurrentConnConfig()
	if connCfg == nil {
		return false
	}
	for _, reqConn := range connCfg.Require {
		if cfg, ok := f.ConnectionMap[reqConn]; !ok || !cfg.Verified {
			return false
		}
	}
	return true
}

// HasIdentifiedUser 是否存在待关联的已有用户（User 已设但 State 仍为 Initialized）
func (f *AuthFlow) HasIdentifiedUser() bool {
	return f.User != nil && f.State == FlowStateInitialized
}

// SetAuthorized 设置为已授权状态
func (f *AuthFlow) SetAuthorized(grantedScopes []string) {
	f.State = FlowStateAuthorized
	f.GrantedScopes = grantedScopes
}

// SetCompleted 设置为已完成状态
func (f *AuthFlow) SetCompleted() {
	f.State = FlowStateCompleted
}

// RevokeVchanVerification 撤销当前 Connection 的 Require 中所有 vchan 类型 connection 的验证状态
// 风控触发时调用：重置 vchan 的 Verified=false，强制用户重新完成人机验证
// 返回 true 表示至少撤销了一个 vchan（风控生效），false 表示无 vchan 可撤销（降级为纯频率限制）
func (f *AuthFlow) RevokeVchanVerification() bool {
	connCfg := f.GetCurrentConnConfig()
	if connCfg == nil {
		return false
	}
	revoked := false
	for _, reqConn := range connCfg.Require {
		if cfg, ok := f.ConnectionMap[reqConn]; ok && cfg.Type == ConnTypeVChan {
			cfg.Verified = false
			revoked = true
		}
	}
	return revoked
}

// AuthErrorInterface 定义 AuthError 的接口，用于解耦
type AuthErrorInterface interface {
	error
	GetHTTPStatus() int
	GetCode() string
	GetDescription() string
	GetData() map[string]any
}

// Fail 设置错误状态并阻断流程
func (f *AuthFlow) Fail(err AuthErrorInterface) {
	f.State = FlowStateFailed
	f.Error = &FlowError{
		HTTPStatus:  err.GetHTTPStatus(),
		Code:        err.GetCode(),
		Description: err.GetDescription(),
		Data:        err.GetData(),
	}
}

// HasError 检查是否有错误
func (f *AuthFlow) HasError() bool {
	return f.Error != nil || f.State == FlowStateFailed
}

// ==================== Extra ====================

// SetExtra 设置额外数据
func (f *AuthFlow) SetExtra(key, value string) {
	if f.Extra == nil {
		f.Extra = make(map[string]string)
	}
	f.Extra[key] = value
}

// GetExtra 获取额外数据
func (f *AuthFlow) GetExtra(key string) string {
	if f.Extra == nil {
		return ""
	}
	return f.Extra[key]
}
