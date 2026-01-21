package models

import (
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/heliannuuthus/helios/internal/auth"
)

// User 用户
type User struct {
	ID            uint        `gorm:"primaryKey;autoIncrement;column:_id"`
	Domain        auth.Domain `json:"domain" gorm:"column:domain;size:32;not null;index"`
	OpenID        string      `json:"id" gorm:"column:openid;size:64;not null;uniqueIndex"`
	Name          string      `json:"name" gorm:"column:name;size:128"`
	Picture       string      `json:"picture" gorm:"column:picture;size:512"`
	Email         *string     `json:"email" gorm:"column:email;size:256;index"`
	EmailVerified bool        `json:"email_verified" gorm:"column:email_verified;default:false"`
	Phone         *string     `json:"-" gorm:"column:phone;size:64;index"`   // 手机号哈希
	PhoneCipher   *string     `json:"-" gorm:"column:phone_cipher;size:256"` // 手机号密文
	Status        int8        `json:"status" gorm:"column:status;default:0"` // 0=active, 1=disabled
	LastLoginAt   time.Time   `json:"last_login_at" gorm:"column:last_login_at"`
	CreatedAt     time.Time   `json:"created_at" gorm:"column:created_at"`
	UpdatedAt     time.Time   `json:"updated_at" gorm:"column:updated_at"`
}

func (User) TableName() string {
	return "t_user"
}

// IsActive 用户是否活跃
func (u *User) IsActive() bool {
	return u.Status == 0
}

// UserIdentity 用户身份（IDP 绑定）
// 注意：用户在没有互相绑定之前允许具有多个身份
type UserIdentity struct {
	ID        uint      `gorm:"primaryKey;autoIncrement;column:_id"`
	OpenID    string    `gorm:"column:openid;size:64;not null;index"`
	IDP       auth.IDP  `gorm:"column:idp;size:64;not null;uniqueIndex:uk_idp_t_openid,priority:1"`
	TOpenID   string    `gorm:"column:t_openid;size:256;not null;uniqueIndex:uk_idp_t_openid,priority:2"` // 第三方原始标识
	RawData   string    `gorm:"column:raw_data;type:text"`
	CreatedAt time.Time `gorm:"column:created_at"`
	UpdatedAt time.Time `gorm:"column:updated_at"`
}

func (UserIdentity) TableName() string {
	return "t_user_identity"
}

// GenerateOpenID 生成用户 OpenID
func GenerateOpenID() string {
	bytes := make([]byte, 16)
	_, _ = rand.Read(bytes)
	return hex.EncodeToString(bytes)
}
