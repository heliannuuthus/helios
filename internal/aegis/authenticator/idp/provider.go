package idp

import (
	"context"

	"github.com/heliannuuthus/helios/internal/aegis/types"
	"github.com/heliannuuthus/helios/internal/hermes/models"
)

// Provider IDP 提供者接口
type Provider interface {
	// Type 返回 IDP 类型标识
	Type() string

	// Login 执行登录认证
	// proof: 认证凭证（OAuth code / password / OTP code）
	// params: 额外参数（如 identifier）
	// 返回: 第三方 IDP 用户信息的通用模型
	Login(ctx context.Context, proof string, params ...any) (*models.TUserInfo, error)

	// FetchAdditionalInfo 补充获取用户信息（手机号、邮箱等）
	// infoType: "phone", "email", "realname" 等
	// params: 通用参数，不同 IDP 需要不同参数
	FetchAdditionalInfo(ctx context.Context, infoType string, params ...any) (*AdditionalInfo, error)

	// Prepare 准备前端所需的公开配置（不含密钥）
	// 返回 ConnectionConfig，包含 connection 标识和可选的 identifier（如 client_id）
	Prepare() *types.ConnectionConfig
}

// AdditionalInfo 补充信息结果
type AdditionalInfo struct {
	Type  string         `json:"type"`            // "phone", "email" 等
	Value string         `json:"value"`           // 具体值
	Extra map[string]any `json:"extra,omitempty"` // 额外数据
}
