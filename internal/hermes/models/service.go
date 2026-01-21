package models

import (
	"time"
)

// Service 服务
type Service struct {
	ID                    uint      `gorm:"primaryKey;autoIncrement;column:_id"`
	ServiceID             string    `gorm:"column:service_id;size:32;not null;uniqueIndex"`
	DomainID              string    `gorm:"column:domain_id;size:32;not null;index"`
	Name                  string    `gorm:"column:name;size:128;not null"`
	Description           *string   `gorm:"column:description;type:text"`
	EncryptedKey          string    `gorm:"column:encrypted_key;type:text;not null"`
	AccessTokenExpiresIn  int       `gorm:"column:access_token_expires_in;default:7200"`
	RefreshTokenExpiresIn int       `gorm:"column:refresh_token_expires_in;default:604800"`
	Status                int8      `gorm:"column:status;default:0"` // 0=active, 1=disabled
	CreatedAt             time.Time `gorm:"column:created_at;not null"`
	UpdatedAt             time.Time `gorm:"column:updated_at;not null"`
}

func (Service) TableName() string {
	return "t_service"
}
