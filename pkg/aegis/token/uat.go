package token

import (
	"fmt"
	"time"

	"aidanwoods.dev/go-paseto"
)

// UserAccessToken 用户访问令牌
// 包含用户身份信息，用户信息加密后存储在 footer 中
type UserAccessToken struct {
	Claims             // 内嵌基础 Claims
	scope       string // 授权范围
	openID      string // 对外标识（主身份 t_openid，作为 sub 对外暴露）
	internalUID string // 内部用户 ID（t_user.openid，不对外暴露，用于内部查询）
	nickname    string // 昵称
	picture     string // 头像
	email       string // 邮箱
	phone       string // 手机号
}

// ==================== UAT TokenTypeBuilder ====================

// UAT UAT 类型构建器，实现 TokenTypeBuilder 接口
type UAT struct {
	scope       string
	openID      string
	internalUID string
	nickname    string
	picture     string
	email       string
	phone       string
}

// NewUserAccessTokenBuilder 创建 UAT 类型构建器
func NewUserAccessTokenBuilder() *UAT {
	return &UAT{}
}

// Scope 设置授权范围
func (u *UAT) Scope(scope string) *UAT {
	u.scope = scope
	return u
}

// OpenID 设置用户对外标识（主身份 t_openid）
func (u *UAT) OpenID(openID string) *UAT {
	u.openID = openID
	return u
}

// InternalUID 设置用户内部 ID（t_user.openid，不对外暴露）
func (u *UAT) InternalUID(uid string) *UAT {
	u.internalUID = uid
	return u
}

// Nickname 设置用户昵称
func (u *UAT) Nickname(nickname string) *UAT {
	u.nickname = nickname
	return u
}

// Picture 设置用户头像
func (u *UAT) Picture(picture string) *UAT {
	u.picture = picture
	return u
}

// Email 设置用户邮箱
func (u *UAT) Email(email string) *UAT {
	u.email = email
	return u
}

// Phone 设置用户手机号
func (u *UAT) Phone(phone string) *UAT {
	u.phone = phone
	return u
}

// build 实现 TokenTypeBuilder 接口
func (u *UAT) build(claims Claims) Token {
	uat := &UserAccessToken{
		Claims:      claims,
		scope:       u.scope,
		openID:      u.openID,
		internalUID: u.internalUID,
	}

	// 根据 scope 过滤用户信息
	if u.openID != "" {
		scopeSet := parseScopeSet(u.scope)

		if scopeSet["profile"] {
			uat.nickname = u.nickname
			uat.picture = u.picture
		}
		if scopeSet["email"] {
			uat.email = u.email
		}
		if scopeSet["phone"] {
			uat.phone = u.phone
		}
	}

	return uat
}

// ==================== 解析函数 ====================

// ParseUserAccessToken 从 PASETO Token 解析 UserAccessToken（用于验证后）
func ParseUserAccessToken(pasetoToken *paseto.Token) (*UserAccessToken, error) {
	claims, err := ParseClaims(pasetoToken)
	if err != nil {
		return nil, fmt.Errorf("parse claims: %w", err)
	}

	var scope string
	if err := pasetoToken.Get("scope", &scope); err != nil {
		// scope 是可选字段
		scope = ""
	}

	return &UserAccessToken{
		Claims: claims,
		scope:  scope,
	}, nil
}

// ==================== Token 接口实现 ====================

// Type 实现 Token 接口
func (u *UserAccessToken) Type() TokenType {
	return TokenTypeUAT
}

// build 实现 tokenBuilder 接口（小写，内部使用）
func (u *UserAccessToken) build() (*paseto.Token, error) {
	return u.BuildPaseto()
}

// BuildPaseto 构建 PASETO Token（不包含签名）
// 注意：用户信息需要加密后放入 footer，由 Service 处理
func (u *UserAccessToken) BuildPaseto() (*paseto.Token, error) {
	t := paseto.NewToken()
	if err := u.SetStandardClaims(&t); err != nil {
		return nil, fmt.Errorf("set standard claims: %w", err)
	}
	if err := t.Set("scope", u.scope); err != nil {
		return nil, fmt.Errorf("set scope: %w", err)
	}
	return &t, nil
}

// ExpiresIn 实现 AccessToken 接口
func (u *UserAccessToken) ExpiresIn() time.Duration {
	return u.GetExpiresIn()
}

// GetScope 返回授权范围
func (u *UserAccessToken) GetScope() string {
	return u.scope
}

// HasScope 检查是否包含某个 scope
func (u *UserAccessToken) HasScope(scope string) bool {
	return HasScope(u.scope, scope)
}

// ==================== 用户信息 Getter ====================

// GetOpenID 返回用户对外标识（主身份 t_openid，即 token 的 sub）
func (u *UserAccessToken) GetOpenID() string {
	return u.openID
}

// GetInternalUID 返回用户内部 ID（t_user.openid，用于内部查询）
func (u *UserAccessToken) GetInternalUID() string {
	return u.internalUID
}

// GetNickname 返回用户昵称
func (u *UserAccessToken) GetNickname() string {
	return u.nickname
}

// GetPicture 返回用户头像
func (u *UserAccessToken) GetPicture() string {
	return u.picture
}

// GetEmail 返回用户邮箱
func (u *UserAccessToken) GetEmail() string {
	return u.email
}

// GetPhone 返回用户手机号
func (u *UserAccessToken) GetPhone() string {
	return u.phone
}

// HasUser 检查是否有用户信息
func (u *UserAccessToken) HasUser() bool {
	return u.openID != ""
}

// ==================== 内部方法 ====================

// SetUserInfo 设置用户信息（供 interpreter 解密后调用）
func (u *UserAccessToken) SetUserInfo(openID, internalUID, nickname, picture, email, phone string) {
	u.openID = openID
	u.internalUID = internalUID
	u.nickname = nickname
	u.picture = picture
	u.email = email
	u.phone = phone
}

// GetUserForFooter 获取用于 footer 加密的用户信息（返回可序列化的 map）
func (u *UserAccessToken) GetUserForFooter() map[string]string {
	if u.openID == "" {
		return nil
	}
	result := make(map[string]string)
	if u.openID != "" {
		result["sub"] = u.openID
	}
	if u.internalUID != "" {
		result["uid"] = u.internalUID
	}
	if u.nickname != "" {
		result["nickname"] = u.nickname
	}
	if u.picture != "" {
		result["picture"] = u.picture
	}
	if u.email != "" {
		result["email"] = u.email
	}
	if u.phone != "" {
		result["phone"] = u.phone
	}
	return result
}
