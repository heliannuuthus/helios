package models

import "time"

// DomainRecord 域表（t_domain）持久化模型
type DomainRecord struct {
	DomainID    string    `gorm:"column:domain_id;size:32;primaryKey" json:"domain_id"`
	Name        string    `gorm:"column:name;size:128;not null" json:"name"`
	Description *string   `gorm:"column:description;size:512" json:"description,omitempty"`
	CreatedAt   time.Time `gorm:"column:created_at;not null" json:"created_at"`
	UpdatedAt   time.Time `gorm:"column:updated_at;not null" json:"updated_at"`
}

func (DomainRecord) TableName() string {
	return "t_domain"
}

// DomainIDPRecord 域允许的 IDP 表（t_domain_idp）
type DomainIDPRecord struct {
	DomainID  string    `gorm:"column:domain_id;size:32;primaryKey" json:"domain_id"`
	IDPType   string    `gorm:"column:idp_type;size:32;primaryKey" json:"idp_type"`
	CreatedAt time.Time `gorm:"column:created_at;not null" json:"created_at"`
}

func (DomainIDPRecord) TableName() string {
	return "t_domain_idp"
}

// IDPKey IDP 密钥表（t_idp_key）
// 全局存储第三方 IDP 凭证，(idp_type, t_app_id) 唯一
type IDPKey struct {
	ID        uint      `gorm:"primaryKey;autoIncrement;column:_id" json:"_id"`
	IDPType   string    `gorm:"column:idp_type;size:32;not null" json:"idp_type"`
	TAppID    string    `gorm:"column:t_app_id;size:256;not null" json:"t_app_id"`
	TSecret   string    `gorm:"column:t_secret;size:2048;not null" json:"-"`
	CreatedAt time.Time `gorm:"column:created_at;not null" json:"created_at"`
	UpdatedAt time.Time `gorm:"column:updated_at;not null" json:"updated_at"`
}

func (IDPKey) TableName() string {
	return "t_idp_key"
}

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

func (DomainIDPConfig) TableName() string {
	return "t_domain_idp_config"
}
