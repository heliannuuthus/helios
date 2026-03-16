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
