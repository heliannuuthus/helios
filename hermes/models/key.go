package models

import "time"

// Key 签名密钥（t_key）
type Key struct {
	ID           uint       `gorm:"primaryKey;autoIncrement;column:_id"`
	OwnerType    string     `gorm:"column:owner_type;size:16;not null"`
	OwnerID      string     `gorm:"column:owner_id;size:64;not null"`
	EncryptedKey string     `gorm:"column:encrypted_key;size:256;not null"`
	ExpiredAt    *time.Time `gorm:"column:expired_at"`
	CreatedAt    time.Time  `gorm:"column:created_at;not null"`
}

func (Key) TableName() string {
	return "t_key"
}

func (k Key) PrimaryKey() uint {
	return k.ID
}

const (
	KeyOwnerApplication = "application"
	KeyOwnerService     = "service"
)
