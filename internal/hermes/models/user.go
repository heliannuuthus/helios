package models

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// User 用户模型
// OpenID = 该域下 global 身份的 t_openid，即对外用户标识
// 一个物理用户在不同域下有不同的 OpenID，对应不同的 t_user 记录
type User struct {
	// 主键
	ID uint `gorm:"primaryKey;autoIncrement;column:_id"`
	// 业务字段
	OpenID        string  `json:"openid" gorm:"column:openid;size:64;not null;uniqueIndex"` // 用户标识（= global identity 的 t_openid）
	Status        int8    `json:"status" gorm:"column:status;not null;default:0"`           // 0=active, 1=disabled
	Username      *string `json:"-" gorm:"column:username;size:64;uniqueIndex"`             // 用户名（唯一）
	PasswordHash  *string `json:"-" gorm:"column:password_hash;size:256"`                   // 密码哈希（bcrypt）
	Nickname      *string `json:"nickname" gorm:"column:nickname;size:128"`
	Picture       *string `json:"picture" gorm:"column:picture;size:512"`
	Email         *string `json:"email" gorm:"column:email;size:256;uniqueIndex"`
	EmailVerified bool    `json:"email_verified" gorm:"column:email_verified;not null;default:false"`
	Phone         *string `json:"-" gorm:"column:phone;size:64;uniqueIndex"` // 手机号哈希
	PhoneCipher   *string `json:"-" gorm:"column:phone_cipher;size:256"`     // 手机号密文
	// 时间戳
	LastLoginAt *time.Time `json:"last_login_at" gorm:"column:last_login_at"`
	CreatedAt   time.Time  `json:"created_at" gorm:"column:created_at;not null"`
	UpdatedAt   time.Time  `json:"updated_at" gorm:"column:updated_at;not null"`
}

func (User) TableName() string {
	return "t_user"
}

// IsActive 用户是否活跃
func (u *User) IsActive() bool {
	return u.Status == 0
}

// UserIdentity 用户身份（IDP 绑定），每个身份归属一个域
type UserIdentity struct {
	// 主键
	ID uint `gorm:"primaryKey;autoIncrement;column:_id"`
	// 业务字段
	Domain  string `gorm:"column:domain;size:16;not null;uniqueIndex:uk_domain_idp_t_openid,priority:1"`
	OpenID  string `gorm:"column:openid;size:64;not null;index"`
	IDP     string `gorm:"column:idp;size:64;not null;uniqueIndex:uk_domain_idp_t_openid,priority:2"`
	TOpenID string `gorm:"column:t_openid;size:256;not null;uniqueIndex:uk_domain_idp_t_openid,priority:3"`
	RawData string `gorm:"column:raw_data;type:text"`
	// 时间戳
	CreatedAt time.Time `gorm:"column:created_at;not null"`
	UpdatedAt time.Time `gorm:"column:updated_at;not null"`
}

func (UserIdentity) TableName() string {
	return "t_user_identity"
}

// Identities 用户身份列表，提供按条件快速检索的便捷方法
type Identities []*UserIdentity

// FindByIDP 根据 IDP 类型查找身份（如按 connection 查找）
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

// UserWithDecrypted 解密后的用户信息（业务层使用）
type UserWithDecrypted struct {
	User
	Phone string `json:"phone,omitempty"` // 解密后的手机号
}

// ==================== 实现 token.UserInfo 接口 ====================

// GetOpenID 返回用户标识
func (u *UserWithDecrypted) GetOpenID() string {
	return u.OpenID
}

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
func (u *UserWithDecrypted) GetPhone() string {
	return u.Phone
}

// ==================== 其他方法 ====================

// SafeString 脱敏输出（用于日志）
func (u *UserWithDecrypted) SafeString() string {
	nickname := ""
	if u.Nickname != nil {
		nickname = *u.Nickname
	}
	return fmt.Sprintf("User{OpenID:%s, Nickname:%s, Email:%s, Phone:%s}",
		u.OpenID,
		nickname,
		maskEmail(u.Email),
		maskPhone(u.Phone),
	)
}

// String 实现 Stringer 接口，打印时自动脱敏
func (u *UserWithDecrypted) String() string {
	return u.SafeString()
}

// base62Chars base62 编码字符集
const base62Chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// base62Encode 将字节切片编码为 base62 字符串
func base62Encode(data []byte) string {
	n := new(big.Int).SetBytes(data)
	if n.Sign() == 0 {
		return string(base62Chars[0])
	}

	base := big.NewInt(62)
	mod := new(big.Int)
	var result []byte

	for n.Sign() > 0 {
		n.DivMod(n, base, mod)
		result = append(result, base62Chars[mod.Int64()])
	}

	// 反转
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}

	return string(result)
}

// generateRandomBase62 生成指定字节数的随机数据并 base62 编码
func generateRandomBase62(byteLen int) string {
	b := make([]byte, byteLen)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("generate random id failed: %v", err))
	}
	return base62Encode(b)
}

// GenerateOpenID 生成用户标识（128 位随机，base62 编码，~22 字符）
// 同时作为 t_user.openid 和 global identity 的 t_openid
func GenerateOpenID() string {
	return generateRandomBase62(16)
}

// maskEmail 邮箱脱敏：a**@example.com
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

// maskPhone 手机号脱敏：138****1234
func maskPhone(phone string) string {
	if phone == "" {
		return ""
	}
	if len(phone) <= 7 {
		return phone
	}
	return phone[:3] + "****" + phone[len(phone)-4:]
}

// TUserInfo 第三方 IDP 返回的用户信息（通用模型）
// 各 IDP Provider 的 Login() 方法统一返回此类型
// IDP 胶水层从此类型构造 UserIdentity 存入 AuthFlow
type TUserInfo struct {
	TOpenID  string `json:"t_openid"`           // 第三方用户唯一标识（IDP 返回的 openid）
	Nickname string `json:"nickname,omitempty"` // 昵称/显示名
	Email    string `json:"email,omitempty"`    // 邮箱
	Phone    string `json:"phone,omitempty"`    // 手机号
	Picture  string `json:"picture,omitempty"`  // 头像 URL
	RawData  string `json:"raw_data,omitempty"` // IDP 返回的原始数据（JSON）
}

// ToUserIdentity 将 TUserInfo 转换为 UserIdentity
func (t *TUserInfo) ToUserIdentity(domain, idp string) *UserIdentity {
	return &UserIdentity{
		Domain:  domain,
		IDP:     idp,
		TOpenID: t.TOpenID,
		RawData: t.RawData,
	}
}
