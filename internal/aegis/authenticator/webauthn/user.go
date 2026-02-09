package webauthn

import (
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/heliannuuthus/helios/internal/hermes/models"
)

// User 实现 webauthn.User 接口
// 用于 WebAuthn 注册和认证流程
type User struct {
	user        *models.UserWithDecrypted
	credentials []webauthn.Credential
}

// NewUser 创建 WebAuthn 用户
func NewUser(user *models.UserWithDecrypted, credentials []webauthn.Credential) *User {
	return &User{
		user:        user,
		credentials: credentials,
	}
}

// WebAuthnID 返回用户的唯一标识（用于 WebAuthn）
func (u *User) WebAuthnID() []byte {
	return []byte(u.user.UID)
}

// WebAuthnName 返回用户名（用于显示）
func (u *User) WebAuthnName() string {
	// 优先使用邮箱，其次使用 UID
	if u.user.Email != nil && *u.user.Email != "" {
		return *u.user.Email
	}
	return u.user.UID
}

// WebAuthnDisplayName 返回显示名称
func (u *User) WebAuthnDisplayName() string {
	if u.user.Nickname != nil && *u.user.Nickname != "" {
		return *u.user.Nickname
	}
	return u.WebAuthnName()
}

// WebAuthnCredentials 返回用户已注册的凭证列表
func (u *User) WebAuthnCredentials() []webauthn.Credential {
	return u.credentials
}

// WebAuthnIcon 返回用户头像（已弃用，但接口需要）
func (u *User) WebAuthnIcon() string {
	if u.user.Picture != nil {
		return *u.user.Picture
	}
	return ""
}

// GetUID 获取用户 UID
func (u *User) GetUID() string {
	return u.user.UID
}
