// Package types provides type definitions for the Auth module.
// nolint:revive // This package name follows Go conventions for internal type packages.
package types

import (
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/heliannuuthus/helios/internal/hermes/models"
	"github.com/heliannuuthus/helios/pkg/json"
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

// AuthFlow 认证流程上下文
// auth session = flowID
type AuthFlow struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	State     FlowState `json:"state"`

	// 请求参数
	Request *AuthRequest `json:"request"`

	// 实体信息（认证过程中填充）
	Application *models.ApplicationWithKey `json:"application,omitempty"`
	Service     *models.ServiceWithKey     `json:"service,omitempty"`
	User        *models.UserWithDecrypted  `json:"user,omitempty"`

	// Connection 配置
	ConnectionMap map[string]*ConnectionConfig `json:"connection_map,omitempty"` // 所有可用的 Connection 配置
	Connection    string                       `json:"connection,omitempty"`     // 当前使用的 Connection（已认证则不可回退）

	// 认证结果
	ProviderID string `json:"provider_id,omitempty"` // 认证源侧用户标识
	IsNewUser  bool   `json:"is_new_user,omitempty"` // 是否新用户

	// 授权结果
	GrantedScopes []string `json:"granted_scopes,omitempty"`

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
	ResponseType        string `json:"response_type" form:"response_type" binding:"required,oneof=code"`
	ClientID            string `json:"client_id" form:"client_id" binding:"required"`
	Audience            string `json:"audience" form:"audience" binding:"required"`
	RedirectURI         string `json:"redirect_uri" form:"redirect_uri" binding:"required"`
	CodeChallenge       string `json:"code_challenge" form:"code_challenge" binding:"required"`
	CodeChallengeMethod string `json:"code_challenge_method" form:"code_challenge_method" binding:"required,oneof=S256"`
	State               string `json:"state,omitempty" form:"state"`
	Scope               string `json:"scope,omitempty" form:"scope"`

	// 扩展参数 - 序列化时平铺到顶层
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
}

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

// ParseScopes 解析 scope 字符串为列表
func (r *AuthRequest) ParseScopes() []string {
	if r.Scope == "" {
		return nil
	}
	scopes := make([]string, 0)
	for _, s := range splitScopes(r.Scope) {
		if s != "" {
			scopes = append(scopes, s)
		}
	}
	return scopes
}

// splitScopes 按空格分割 scope
func splitScopes(scope string) []string {
	var result []string
	current := ""
	for _, c := range scope {
		if c == ' ' {
			if current != "" {
				result = append(result, current)
				current = ""
			}
		} else {
			current += string(c)
		}
	}
	if current != "" {
		result = append(result, current)
	}
	return result
}

// AuthorizationCode 授权码
type AuthorizationCode struct {
	Code      string    `json:"code"`
	FlowID    string    `json:"flow_id"`
	State     string    `json:"state"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Used      bool      `json:"used"`
}

// ConnectionConfig Connection 配置（返回给前端的公开配置）
type ConnectionConfig struct {
	ID            string                 `json:"id"`                       // 唯一标识（如 "wechat-mp-prod"）
	ProviderType  string                 `json:"provider_type"`            // IDP 类型（如 "wechat:mp"）
	Name          string                 `json:"name,omitempty"`           // 显示名称
	ClientID      string                 `json:"client_id,omitempty"`      // IDP 的 AppID（公开）
	AllowedScopes []string               `json:"allowed_scopes,omitempty"` // 允许的 scope
	Capture       *CaptureConfig         `json:"capture,omitempty"`        // 人机验证配置
	Extra         map[string]interface{} `json:"extra,omitempty"`          // 其他配置
}

// CaptureConfig 人机验证配置
type CaptureConfig struct {
	Required bool   `json:"required"`
	Type     string `json:"type,omitempty"`
	SiteKey  string `json:"site_key,omitempty"`
}

// LoginRequest 登录请求
type LoginRequest struct {
	Connection string         `json:"connection" binding:"required"` // 身份提供方（IDP）
	Data       map[string]any `json:"data" binding:"required"`       // Connection 需要的数据
}

// ==================== 辅助函数 ====================

// GenerateFlowID 生成 Flow ID
func GenerateFlowID() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		// 如果加密随机数生成失败，使用时间戳作为备选
		return "flow_" + hex.EncodeToString([]byte(time.Now().Format("20060102150405.000000000")))
	}
	return "flow_" + hex.EncodeToString(bytes)
}

// GenerateAuthorizationCode 生成授权码
func GenerateAuthorizationCode() string {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		// 如果加密随机数生成失败，使用时间戳作为备选
		return hex.EncodeToString([]byte(time.Now().Format("20060102150405.000000000")))
	}
	return hex.EncodeToString(bytes)
}

// NewAuthFlow 创建新的 AuthFlow
func NewAuthFlow(req *AuthRequest, ttl time.Duration) *AuthFlow {
	now := time.Now()
	return &AuthFlow{
		ID:        GenerateFlowID(),
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
		State:     FlowStateInitialized,
		Request:   req,
	}
}

// IsExpired 检查是否已过期
func (f *AuthFlow) IsExpired() bool {
	return time.Now().After(f.ExpiresAt)
}

// CanAuthenticate 检查是否可以进行认证
func (f *AuthFlow) CanAuthenticate() bool {
	return f.State == FlowStateInitialized && !f.IsExpired()
}

// CanAuthorize 检查是否可以进行授权
func (f *AuthFlow) CanAuthorize() bool {
	return f.State == FlowStateAuthenticated && !f.IsExpired()
}

// SetAuthenticated 设置为已认证状态
func (f *AuthFlow) SetAuthenticated(connection, providerID string, user *models.UserWithDecrypted, isNewUser bool) {
	f.State = FlowStateAuthenticated
	f.Connection = connection
	f.ProviderID = providerID
	f.User = user
	f.IsNewUser = isNewUser
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

// AuthErrorInterface 定义 AuthError 的接口，用于解耦
type AuthErrorInterface interface {
	error
	GetHTTPStatus() int
	GetCode() string
	GetDescription() string
	GetData() map[string]any
}

// SetError 设置错误状态并阻断流程
func (f *AuthFlow) SetError(httpStatus int, code, description string, data map[string]any) {
	f.State = FlowStateFailed
	f.Error = &FlowError{
		HTTPStatus:  httpStatus,
		Code:        code,
		Description: description,
		Data:        data,
	}
}

// Fail 使用 AuthError 设置错误状态
func (f *AuthFlow) Fail(err AuthErrorInterface) {
	f.SetError(err.GetHTTPStatus(), err.GetCode(), err.GetDescription(), err.GetData())
}

// HasError 检查是否有错误
func (f *AuthFlow) HasError() bool {
	return f.Error != nil || f.State == FlowStateFailed
}

// GetError 获取错误信息
func (f *AuthFlow) GetError() *FlowError {
	return f.Error
}
