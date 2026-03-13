package models

import "time"

// Key 签名密钥（t_key）
type Key struct {
	ID           uint       `gorm:"primaryKey;autoIncrement;column:_id" json:"_id"`
	OwnerType    string     `gorm:"column:owner_type;size:16;not null" json:"owner_type"`
	OwnerID      string     `gorm:"column:owner_id;size:64;not null" json:"owner_id"`
	EncryptedKey string     `gorm:"column:encrypted_key;size:256;not null" json:"-"` // 不序列化到 API
	ExpiredAt    *time.Time `gorm:"column:expired_at" json:"expired_at,omitempty"`
	CreatedAt    time.Time  `gorm:"column:created_at;not null" json:"created_at"`
}

func (Key) TableName() string {
	return "t_key"
}

const (
	KeyOwnerApplication = "application"
	KeyOwnerService     = "service"
	KeyOwnerDomain      = "domain"
)
