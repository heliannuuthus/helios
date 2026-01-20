package models

import (
	"time"
)

// Application 应用
type Application struct {
	ID          uint      `gorm:"primaryKey;autoIncrement;column:_id"`
	DomainID    string    `gorm:"column:domain_id;size:32;not null;index"`
	AppID       string    `gorm:"column:app_id;size:64;not null;uniqueIndex"`
	Name        string    `gorm:"column:name;size:128;not null"`
	RedirectURIs *string  `gorm:"column:redirect_uris;type:text"` // JSON 数组
	EncryptedKey *string  `gorm:"column:encrypted_key;type:text"` // NULL 表示无密钥
	CreatedAt   time.Time `gorm:"column:created_at;not null"`
	UpdatedAt   time.Time `gorm:"column:updated_at;not null"`
}

func (Application) TableName() string {
	return "t_application"
}

// ApplicationServiceRelation 应用可访问的服务和关系
type ApplicationServiceRelation struct {
	ID        uint      `gorm:"primaryKey;autoIncrement;column:_id"`
	AppID     string    `gorm:"column:app_id;size:64;not null;index"`
	ServiceID string    `gorm:"column:service_id;size:32;not null;index"`
	Relation  string    `gorm:"column:relation;size:32;not null"`
	CreatedAt time.Time `gorm:"column:created_at;not null"`
}

func (ApplicationServiceRelation) TableName() string {
	return "t_application_service_relation"
}
