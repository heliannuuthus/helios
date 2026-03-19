package models

import "time"

// Key 签名密钥（t_key）
type Key struct {
	ID           uint       `gorm:"primaryKey;autoIncrement;column:_id" json:"_id"`
	OwnerType    string     `gorm:"column:owner_type;size:16;not null" json:"owner_type"`
	OwnerID      string     `gorm:"column:owner_id;size:64;not null" json:"owner_id"`
	EncryptedKey string     `gorm:"column:encrypted_key;size:256;not null" json:"-"`
	ExpiredAt    *time.Time `gorm:"column:expired_at" json:"expired_at,omitempty"`
	CreatedAt    time.Time  `gorm:"column:created_at;not null" json:"created_at"`
}

func (Key) TableName() string { return "t_key" }

func (k Key) PrimaryKey() uint { return k.ID }

const (
	KeyOwnerApplication = "application"
	KeyOwnerService     = "service"
	KeyOwnerDomain      = "domain"
)

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

func (IDPKey) TableName() string { return "t_idp_key" }
