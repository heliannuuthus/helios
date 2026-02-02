package models

import (
	"time"
)

// Application 应用
type Application struct {
	// 主键
	ID uint `gorm:"primaryKey;autoIncrement;column:_id"`
	// 固定长度字段
	AppID    string `gorm:"column:app_id;size:64;not null;uniqueIndex"`
	DomainID string `gorm:"column:domain_id;size:32;not null;index"`
	// 时间戳
	CreatedAt time.Time `gorm:"column:created_at;not null"`
	UpdatedAt time.Time `gorm:"column:updated_at;not null"`
	// 变长字段
	Name           string  `gorm:"column:name;size:128;not null"`
	LogoURL        *string `gorm:"column:logo_url;size:512"`         // 应用 Logo URL
	EncryptedKey   *string `gorm:"column:encrypted_key;size:256"`    // NULL=公开应用
	RedirectURIs   *string `gorm:"column:redirect_uris;size:2048"`   // JSON 数组
	AllowedIDPs    *string `gorm:"column:allowed_idps;size:512"`     // JSON 数组
	AllowedOrigins *string `gorm:"column:allowed_origins;size:1024"` // JSON 数组
}

func (Application) TableName() string {
	return "t_application"
}

// ApplicationServiceRelation 应用服务关系
type ApplicationServiceRelation struct {
	// 主键
	ID uint `gorm:"primaryKey;autoIncrement;column:_id"`
	// 固定长度字段
	AppID     string `gorm:"column:app_id;size:64;not null"`
	ServiceID string `gorm:"column:service_id;size:32;not null;index"`
	Relation  string `gorm:"column:relation;size:32;not null;default:*"`
	// 时间戳
	CreatedAt time.Time `gorm:"column:created_at;not null"`
}

func (ApplicationServiceRelation) TableName() string {
	return "t_application_service_relation"
}
