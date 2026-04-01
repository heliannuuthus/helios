package models

import "time"

// Domain 域（从 proto 转换，不含 GORM 标签）
type Domain struct {
	DomainID    string  `json:"domain_id"`
	Name        string  `json:"name"`
	Description *string `json:"description"`
}

// DomainWithKey 带签名密钥的 Domain（Main/Keys 不序列化到 API）
type DomainWithKey struct {
	Domain
	Main []byte   `json:"-"` // 当前主密钥（48 字节 seed）
	Keys [][]byte `json:"-"` // 所有有效密钥
}

// DomainIDPConfig 域 IDP 配置（有配置即表示该 IDP 在此域下可用）
type DomainIDPConfig struct {
	ID        uint      `json:"id"`
	DomainID  string    `json:"domain_id"`
	IDPType   string    `json:"idp_type"`
	Priority  int       `json:"priority"`
	Strategy  *string   `json:"strategy,omitempty"`
	TAppID    string    `json:"t_app_id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
