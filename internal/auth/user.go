package auth

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

// User 用户
type User struct {
	ID          string    `json:"id" gorm:"primaryKey;column:id;size:64"`
	Domain      Domain    `json:"domain" gorm:"column:domain;size:32;not null;index"`
	Name        string    `json:"name" gorm:"column:name;size:128"`
	Picture     string    `json:"picture" gorm:"column:picture;size:512"`
	Phone       *string   `json:"-" gorm:"column:phone;size:64;index"`         // 手机号哈希
	PhoneCipher *string   `json:"-" gorm:"column:phone_cipher;size:256"`       // 手机号密文
	Status      int8      `json:"status" gorm:"column:status;default:0"`       // 0=active, 1=disabled
	LastLoginAt time.Time `json:"last_login_at" gorm:"column:last_login_at"`
	CreatedAt   time.Time `json:"created_at" gorm:"column:created_at"`
	UpdatedAt   time.Time `json:"updated_at" gorm:"column:updated_at"`
}

func (User) TableName() string {
	return "t_auth_user"
}

// IsActive 用户是否活跃
func (u *User) IsActive() bool {
	return u.Status == 0
}

// ToUserInfo 转换为用户信息响应
func (u *User) ToUserInfo(phone string) *UserInfoResponse {
	return &UserInfoResponse{
		Sub:     u.ID,
		Name:    u.Name,
		Picture: u.Picture,
		Phone:   phone,
		Domain:  u.Domain,
	}
}

// UserIdentity 用户身份（IDP 绑定）
type UserIdentity struct {
	ID         uint      `gorm:"primaryKey;autoIncrement;column:id"`
	UserID     string    `gorm:"column:user_id;size:64;not null;index"`
	IDP        IDP       `gorm:"column:idp;size:64;not null;uniqueIndex:uk_idp_provider_id,priority:1"`
	ProviderID string    `gorm:"column:provider_id;size:256;not null;uniqueIndex:uk_idp_provider_id,priority:2"`
	UnionID    string    `gorm:"column:union_id;size:256;index"` // 联合 ID（微信 UnionID 等）
	RawData    string    `gorm:"column:raw_data;type:text"`
	CreatedAt  time.Time `gorm:"column:created_at"`
	UpdatedAt  time.Time `gorm:"column:updated_at"`
}

func (UserIdentity) TableName() string {
	return "t_auth_user_identity"
}

// RefreshToken 刷新令牌
type RefreshToken struct {
	ID        uint      `gorm:"primaryKey;autoIncrement;column:id"`
	Token     string    `gorm:"column:token;size:128;uniqueIndex"`
	UserID    string    `gorm:"column:user_id;size:64;not null;index"`
	ClientID  string    `gorm:"column:client_id;size:64;not null;index"`
	Scope     string    `gorm:"column:scope;size:256"`
	ExpiresAt time.Time `gorm:"column:expires_at;not null;index"`
	Revoked   bool      `gorm:"column:revoked;default:false"`
	CreatedAt time.Time `gorm:"column:created_at"`
}

func (RefreshToken) TableName() string {
	return "t_auth_refresh_token"
}

// IsValid 检查是否有效
func (r *RefreshToken) IsValid() bool {
	return !r.Revoked && time.Now().Before(r.ExpiresAt)
}

// GenerateUserID 生成用户 ID
func GenerateUserID() string {
	bytes := make([]byte, 16)
	_, _ = rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// GenerateRefreshTokenValue 生成刷新令牌
func GenerateRefreshTokenValue() string {
	bytes := make([]byte, 32)
	_, _ = rand.Read(bytes)
	return hex.EncodeToString(bytes)
}
