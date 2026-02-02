package models

import (
	"time"
)

// Service 服务
type Service struct {
	// 主键
	ID uint `gorm:"primaryKey;autoIncrement;column:_id"`
	// 固定长度字段
	ServiceID             string `gorm:"column:service_id;size:32;not null;uniqueIndex"`
	DomainID              string `gorm:"column:domain_id;size:32;not null"`
	AccessTokenExpiresIn  uint   `gorm:"column:access_token_expires_in;not null;default:7200"`
	RefreshTokenExpiresIn uint   `gorm:"column:refresh_token_expires_in;not null;default:604800"`
	// 时间戳
	CreatedAt time.Time `gorm:"column:created_at;not null"`
	UpdatedAt time.Time `gorm:"column:updated_at;not null"`
	// 变长字段
	Name               string  `gorm:"column:name;size:128;not null"`
	Description        *string `gorm:"column:description;size:512"`
	EncryptedKey       string  `gorm:"column:encrypted_key;size:256;not null"`
	RequiredIdentities *string `gorm:"column:required_identities;size:512"` // JSON 数组
}

func (Service) TableName() string {
	return "t_service"
}
