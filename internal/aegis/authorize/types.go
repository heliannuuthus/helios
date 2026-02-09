package authorize

// TokenRequest Token 请求
type TokenRequest struct {
	GrantType    string `form:"grant_type" binding:"required,oneof=authorization_code refresh_token"`
	Code         string `form:"code"`          // authorization_code 时必填
	RedirectURI  string `form:"redirect_uri"`  // authorization_code 时必填
	ClientID     string `form:"client_id"`     // 必填
	CodeVerifier string `form:"code_verifier"` // PKCE 验证器
	RefreshToken string `form:"refresh_token"` // refresh_token grant 时必填
}

// TokenResponse Token 响应
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"` // 只有 offline_access 时返回
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"` // 实际授予的 scope
}

// UserInfoResponse 用户信息响应（脱敏）
type UserInfoResponse struct {
	Sub      string `json:"sub"`
	Nickname string `json:"nickname,omitempty"`
	Picture  string `json:"picture,omitempty"`
	Email    string `json:"email,omitempty"` // 脱敏
	Phone    string `json:"phone,omitempty"` // 脱敏
}

// GrantType 授权类型
const (
	GrantTypeAuthorizationCode = "authorization_code"
	GrantTypeRefreshToken      = "refresh_token"
)

// Scope 常量
const (
	ScopeOpenID        = "openid"
	ScopeProfile       = "profile"
	ScopeEmail         = "email"
	ScopePhone         = "phone"
	ScopeOfflineAccess = "offline_access"
)
