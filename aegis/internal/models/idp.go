package models

// TUserInfo 第三方 IDP 返回的用户信息
type TUserInfo struct {
	TOpenID  string `json:"t_openid"`
	Nickname string `json:"nickname,omitempty"`
	Email    string `json:"email,omitempty"`
	Phone    string `json:"phone,omitempty"`
	Picture  string `json:"picture,omitempty"`
	RawData  string `json:"raw_data,omitempty"`
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
