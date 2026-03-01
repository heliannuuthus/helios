package token

import (
	"fmt"
	"time"

	"aidanwoods.dev/go-paseto"
	"github.com/go-json-experiment/json"
)

// UserInfo holds the user identity data that will be encrypted
// into the sub field as a nested v4.local token.
type UserInfo struct {
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
	userInfo *UserInfo
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
		info := &UserInfo{Sub: u.openID}
		scopeSet := parseScopeSet(u.scope)

		if scopeSet[ScopeProfile] {
			info.Nickname = u.nickname
			info.Picture = u.picture
		}
		if scopeSet[ScopeEmail] {
			info.Email = u.email
		}
		if scopeSet[ScopePhone] {
			info.Phone = u.phone
		}
		uat.userInfo = info
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

func (u *UserAccessToken) GetScope() string {
	return u.scope
}

func (u *UserAccessToken) HasScope(scope string) bool {
	return HasScope(u.scope, scope)
}

// ==================== UserInfo Accessors ====================

func (u *UserAccessToken) GetOpenID() string {
	if u.userInfo == nil {
		return ""
	}
	return u.userInfo.Sub
}

func (u *UserAccessToken) GetNickname() string {
	if u.userInfo == nil {
		return ""
	}
	return u.userInfo.Nickname
}

func (u *UserAccessToken) GetPicture() string {
	if u.userInfo == nil {
		return ""
	}
	return u.userInfo.Picture
}

func (u *UserAccessToken) GetEmail() string {
	if u.userInfo == nil {
		return ""
	}
	return u.userInfo.Email
}

func (u *UserAccessToken) GetPhone() string {
	if u.userInfo == nil {
		return ""
	}
	return u.userInfo.Phone
}

func (u *UserAccessToken) HasUser() bool {
	return u.userInfo != nil && u.userInfo.Sub != ""
}

// SetUserInfo sets user info (called after decrypting the sub field).
func (u *UserAccessToken) SetUserInfo(info *UserInfo) {
	u.userInfo = info
}

// GetUserInfo returns the user info struct.
func (u *UserAccessToken) GetUserInfo() *UserInfo {
	return u.userInfo
}

// MarshalUserPayload serializes the user info to JSON for inner token encryption.
func (u *UserAccessToken) MarshalUserPayload() ([]byte, error) {
	if u.userInfo == nil {
		return nil, fmt.Errorf("%w: no user info", ErrMissingClaims)
	}
	return json.Marshal(u.userInfo)
}

// UnmarshalUserInfo deserializes user info from decrypted inner token claims JSON.
func UnmarshalUserInfo(data []byte) (*UserInfo, error) {
	var info UserInfo
	if err := json.Unmarshal(data, &info); err != nil {
		return nil, fmt.Errorf("unmarshal user info: %w", err)
	}
	return &info, nil
}
