package models

import "time"

// Domain 域（元数据与允许的 IDP 来自数据库，签名密钥来自配置/密钥服务）
type Domain struct {
	DomainID    string   `json:"domain_id"`    // 域标识：consumer/platform
	Name        string   `json:"name"`         // 域名称
	Description *string  `json:"description"`  // 域描述
	AllowedIDPs []string `json:"allowed_idps"` // 该域允许的 IDP 类型，应用添加 IDP 时只能从此列表选
}

// DomainWithKey 带签名密钥的 Domain（Main/Keys 不序列化到 API）
type DomainWithKey struct {
	Domain
	Main []byte   `json:"-"` // 当前主密钥（48 字节 seed，用于签发新 token）
	Keys [][]byte `json:"-"` // 所有有效密钥（包括主密钥和轮换中的旧密钥，用于验证）
}

// DomainRecord 域表（t_domain）持久化模型
type DomainRecord struct {
	DomainID    string    `gorm:"column:domain_id;size:32;primaryKey" json:"domain_id"`
	Name        string    `gorm:"column:name;size:128;not null" json:"name"`
	Description *string   `gorm:"column:description;size:512" json:"description,omitempty"`
	CreatedAt   time.Time `gorm:"column:created_at;not null" json:"created_at"`
	UpdatedAt   time.Time `gorm:"column:updated_at;not null" json:"updated_at"`
}

func (DomainRecord) TableName() string { return "t_domain" }

// DomainIDPRecord 域允许的 IDP 表（t_domain_idp）
type DomainIDPRecord struct {
	DomainID  string    `gorm:"column:domain_id;size:32;primaryKey" json:"domain_id"`
	IDPType   string    `gorm:"column:idp_type;size:32;primaryKey" json:"idp_type"`
	CreatedAt time.Time `gorm:"column:created_at;not null" json:"created_at"`
}

func (DomainIDPRecord) TableName() string { return "t_domain_idp" }

// DomainIDPConfig 域 IDP 配置表（t_domain_idp_config）
// 域级别的 IDP 默认配置，引用 t_idp_key 中的 t_app_id
type DomainIDPConfig struct {
	ID        uint      `gorm:"primaryKey;autoIncrement;column:_id" json:"_id"`
	DomainID  string    `gorm:"column:domain_id;size:32;not null" json:"domain_id"`
	IDPType   string    `gorm:"column:idp_type;size:32;not null" json:"idp_type"`
	Priority  int       `gorm:"column:priority;not null;default:0" json:"priority"`
	Strategy  *string   `gorm:"column:strategy;size:256" json:"strategy,omitempty"`
	TAppID    string    `gorm:"column:t_app_id;size:256;not null" json:"t_app_id"`
	CreatedAt time.Time `gorm:"column:created_at;not null" json:"created_at"`
	UpdatedAt time.Time `gorm:"column:updated_at;not null" json:"updated_at"`
}

func (DomainIDPConfig) TableName() string { return "t_domain_idp_config" }
