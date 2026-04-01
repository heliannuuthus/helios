package models

import (
	"fmt"
	"strings"
	"time"
)

// User 用户（从 proto 转换，不含 GORM 标签）
type User struct {
	ID            uint       `json:"_id"`
	OpenID        string     `json:"openid"`
	Status        int8       `json:"status"`
	Username      *string    `json:"-"`
	PasswordHash  *string    `json:"-"`
	Nickname      *string    `json:"nickname"`
	Picture       *string    `json:"picture"`
	Email         *string    `json:"email"`
	EmailVerified bool       `json:"email_verified"`
	Phone         *string    `json:"-"`
	PhoneCipher   *string    `json:"-"`
	LastLoginAt   *time.Time `json:"last_login_at"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

// IsActive 用户是否活跃
func (u *User) IsActive() bool {
	return u.Status == 0
}

// UserIdentity 用户身份（IDP 绑定）
type UserIdentity struct {
	ID        uint      `json:"_id"`
	Domain    string    `json:"domain"`
	UID       string    `json:"uid"`
	IDP       string    `json:"idp"`
	TOpenID   string    `json:"t_openid"`
	RawData   string    `json:"raw_data,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Identities 用户身份列表
type Identities []*UserIdentity

// FindByIDP 根据 IDP 类型查找身份
func (ids Identities) FindByIDP(idp string) *UserIdentity {
	for _, id := range ids {
		if id.IDP == idp {
			return id
		}
	}
	return nil
}

// FindByDomainAndIDP 根据 domain 和 IDP 类型查找身份
func (ids Identities) FindByDomainAndIDP(domain, idp string) *UserIdentity {
	for _, id := range ids {
		if id.Domain == domain && id.IDP == idp {
			return id
		}
	}
	return nil
}

// IDPTypes 提取所有 IDP 类型列表
func (ids Identities) IDPTypes() []string {
	types := make([]string, 0, len(ids))
	for _, id := range ids {
		types = append(types, id.IDP)
	}
	return types
}

// UserWithDecrypted 解密后的用户信息
type UserWithDecrypted struct {
	User
	Phone string `json:"phone,omitempty"`
}

// GetOpenID 返回用户标识
func (u *UserWithDecrypted) GetOpenID() string { return u.OpenID }

// GetNickname 返回用户昵称
func (u *UserWithDecrypted) GetNickname() string {
	if u.Nickname == nil {
		return ""
	}
	return *u.Nickname
}

// GetPicture 返回用户头像
func (u *UserWithDecrypted) GetPicture() string {
	if u.Picture == nil {
		return ""
	}
	return *u.Picture
}

// GetEmail 返回用户邮箱
func (u *UserWithDecrypted) GetEmail() string {
	if u.Email == nil {
		return ""
	}
	return *u.Email
}

// GetPhone 返回用户手机号
func (u *UserWithDecrypted) GetPhone() string { return u.Phone }

// GetMaskedEmail 返回脱敏后的邮箱
func (u *UserWithDecrypted) GetMaskedEmail() string { return maskEmail(u.Email) }

// GetMaskedPhone 返回脱敏后的手机号
func (u *UserWithDecrypted) GetMaskedPhone() string { return maskPhone(u.Phone) }

// SafeString 脱敏输出
func (u *UserWithDecrypted) SafeString() string {
	nickname := ""
	if u.Nickname != nil {
		nickname = *u.Nickname
	}
	return fmt.Sprintf("User{OpenID:%s, Nickname:%s, Email:%s, Phone:%s}",
		u.OpenID, nickname, maskEmail(u.Email), maskPhone(u.Phone))
}

// String 实现 Stringer 接口
func (u *UserWithDecrypted) String() string { return u.SafeString() }

// maskEmail 邮箱脱敏
func maskEmail(email *string) string {
	if email == nil || *email == "" {
		return ""
	}
	e := *email
	parts := strings.Split(e, "@")
	if len(parts) != 2 {
		return e
	}
	local := parts[0]
	if len(local) <= 1 {
		return local + "**@" + parts[1]
	}
	return string(local[0]) + "**@" + parts[1]
}

// maskPhone 手机号脱敏
func maskPhone(phone string) string {
	if phone == "" {
		return ""
	}
	if len(phone) <= 7 {
		return phone
	}
	return phone[:3] + "****" + phone[len(phone)-4:]
}
