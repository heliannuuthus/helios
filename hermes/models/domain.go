package models

import "time"

// Domain 域（元数据来自 t_domain，允许的 IDP 从 t_domain_idp_config 派生）
type Domain struct {
	DomainID    string  `json:"domain_id"`   // 域标识：consumer/platform
	Name        string  `json:"name"`        // 域名称
	Description *string `json:"description"` // 域描述
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

// DomainIDPConfig 域 IDP 配置表（t_domain_idp_config）
// 域级别的 IDP 配置，同时也是域允许使用的 IDP 列表（有配置即允许）
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
