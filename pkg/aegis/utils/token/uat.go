package token

import (
	"fmt"
	"time"

	"aidanwoods.dev/go-paseto"
	"github.com/go-json-experiment/json"
)

// userInfo holds the user identity data that will be encrypted
// into the sub field as a nested v4.local token.
type userInfo struct {
	Sub      string `json:"sub"`
	Nickname string `json:"nickname,omitempty"`
	Picture  string `json:"picture,omitempty"`
	Email    string `json:"email,omitempty"`
	Phone    string `json:"phone,omitempty"`
}

// UserAccessToken represents a user access token.
// User identity data is encrypted in the sub field as a nested v4.local token.
type UserAccessToken struct {
	Claims
	scope    string
	identity *userInfo
}

// ==================== UAT Builder ====================

type UAT struct {
	scope    string
	openID   string
	nickname string
	picture  string
	email    string
	phone    string
}

func NewUserAccessTokenBuilder() *UAT {
	return &UAT{}
}

func (u *UAT) Scope(scope string) *UAT {
	u.scope = scope
	return u
}

func (u *UAT) OpenID(openID string) *UAT {
	u.openID = openID
	return u
}

func (u *UAT) Nickname(nickname string) *UAT {
	u.nickname = nickname
	return u
}

func (u *UAT) Picture(picture string) *UAT {
	u.picture = picture
	return u
}

func (u *UAT) Email(email string) *UAT {
	u.email = email
	return u
}

func (u *UAT) Phone(phone string) *UAT {
	u.phone = phone
	return u
}

func (u *UAT) Build(claims Claims) Token {
	uat := &UserAccessToken{
		Claims: claims,
		scope:  u.scope,
	}

	if u.openID != "" {
		id := &userInfo{Sub: u.openID}
		scopes := ParseScopes(u.scope)

		if _, ok := scopes[ScopeProfile]; ok {
			id.Nickname = u.nickname
			id.Picture = u.picture
		}
		if _, ok := scopes[ScopeEmail]; ok {
			id.Email = u.email
		}
		if _, ok := scopes[ScopePhone]; ok {
			id.Phone = u.phone
		}
		uat.identity = id
	}

	return uat
}

// ==================== Parse ====================

func ParseUserAccessToken(pasetoToken *paseto.Token) (*UserAccessToken, error) {
	claims, err := ParseClaims(pasetoToken)
	if err != nil {
		return nil, fmt.Errorf("parse claims: %w", err)
	}

	var scope string
	if err := pasetoToken.Get(ClaimScope, &scope); err != nil {
		scope = ""
	}

	return &UserAccessToken{
		Claims: claims,
		scope:  scope,
	}, nil
}

func userInfoFromToken(t *paseto.Token) *userInfo {
	info := &userInfo{}
	claims := t.Claims()
	if v, ok := claims["sub"].(string); ok {
		info.Sub = v
	}
	if v, ok := claims["nickname"].(string); ok {
		info.Nickname = v
	}
	if v, ok := claims["picture"].(string); ok {
		info.Picture = v
	}
	if v, ok := claims["email"].(string); ok {
		info.Email = v
	}
	if v, ok := claims["phone"].(string); ok {
		info.Phone = v
	}
	return info
}

// ==================== Token Interface ====================

func (u *UserAccessToken) Type() TokenType {
	return TokenTypeUAT
}

// Build builds the PASETO token claims.
// Note: the sub field is set by the service layer after encryption.
func (u *UserAccessToken) Build() (*paseto.Token, error) {
	t := paseto.NewToken()
	if err := u.SetStandardClaims(&t); err != nil {
		return nil, fmt.Errorf("set standard claims: %w", err)
	}
	if err := t.Set(ClaimScope, u.scope); err != nil {
		return nil, fmt.Errorf("set scope: %w", err)
	}
	return &t, nil
}

func (u *UserAccessToken) ExpiresIn() time.Duration {
	return u.GetExpiresIn()
}

// Scopes 返回 scope 集合。
func (u *UserAccessToken) Scopes() map[string]struct{} {
	return ParseScopes(u.scope)
}

// ==================== Identity Accessors ====================

func (u *UserAccessToken) OpenID() string {
	if u.identity == nil {
		return ""
	}
	return u.identity.Sub
}

func (u *UserAccessToken) Nickname() string {
	if u.identity == nil {
		return ""
	}
	return u.identity.Nickname
}

func (u *UserAccessToken) Picture() string {
	if u.identity == nil {
		return ""
	}
	return u.identity.Picture
}

func (u *UserAccessToken) Email() string {
	if u.identity == nil {
		return ""
	}
	return u.identity.Email
}

func (u *UserAccessToken) Phone() string {
	if u.identity == nil {
		return ""
	}
	return u.identity.Phone
}

// Identified 返回 UAT 是否已关联用户身份。
func (u *UserAccessToken) Identified() bool {
	return u.identity != nil
}

// SetIdentity 设置用户身份信息（解密 sub 字段后调用）。
func (u *UserAccessToken) SetIdentity(t *paseto.Token) {
	u.identity = userInfoFromToken(t)
}

// MarshalIdentity 序列化用户身份信息用于内层 token 加密。
func (u *UserAccessToken) MarshalIdentity() ([]byte, error) {
	if u.identity == nil {
		return nil, fmt.Errorf("%w: no user identity", ErrMissingClaims)
	}
	return json.Marshal(u.identity)
}
