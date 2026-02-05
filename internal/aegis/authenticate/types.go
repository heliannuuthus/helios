package authenticate

import "context"

// EmailSender 邮件发送接口
type EmailSender interface {
	Send(ctx context.Context, to, subject, body string) error
}

// AuthResult 认证结果
type AuthResult struct {
	ProviderID string    // 认证源侧用户标识
	UserInfo   *UserInfo // 用户基础信息（结构化）
	RawData    string    // 原始数据（完整 JSON）
}

// UserInfo 用户基础信息（从各 IDP 提取的通用字段）
type UserInfo struct {
	Nickname string `json:"nickname,omitempty"` // 昵称/显示名
	Email    string `json:"email,omitempty"`    // 邮箱
	Phone    string `json:"phone,omitempty"`    // 手机号
	Picture  string `json:"picture,omitempty"`  // 头像 URL
}
