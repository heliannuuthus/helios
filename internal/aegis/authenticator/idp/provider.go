package idp

import (
	"context"

	"github.com/heliannuuthus/helios/internal/aegis/types"
)

// Provider IDP 提供者接口
type Provider interface {
	// Type 返回 IDP 类型标识
	Type() string

	// Login 执行登录认证
	// proof: 认证凭证（OAuth code / password / OTP code）
	// params: 额外参数（如 identifier）
	Login(ctx context.Context, proof string, params ...any) (*LoginResult, error)

	// FetchAdditionalInfo 补充获取用户信息（手机号、邮箱等）
	// infoType: "phone", "email", "realname" 等
	// params: 通用参数，不同 IDP 需要不同参数
	FetchAdditionalInfo(ctx context.Context, infoType string, params ...any) (*AdditionalInfo, error)

	// Prepare 准备前端所需的公开配置（不含密钥）
	// 返回 ConnectionConfig，包含 connection 标识和可选的 identifier（如 client_id）
	Prepare() *types.ConnectionConfig
}

// LoginResult 登录结果
type LoginResult struct {
	ProviderID string    // IDP 侧用户唯一标识（openid）
	UserInfo   *UserInfo // 用户基础信息（结构化）
	RawData    string    // 原始响应 JSON
}

// UserInfo 用户基础信息（从各 IDP 提取的通用字段）
type UserInfo struct {
	Nickname string `json:"nickname,omitempty"` // 昵称/显示名
	Email    string `json:"email,omitempty"`    // 邮箱
	Phone    string `json:"phone,omitempty"`    // 手机号
	Picture  string `json:"picture,omitempty"`  // 头像 URL
}

// AdditionalInfo 补充信息结果
type AdditionalInfo struct {
	Type  string         `json:"type"`            // "phone", "email" 等
	Value string         `json:"value"`           // 具体值
	Extra map[string]any `json:"extra,omitempty"` // 额外数据
}
