package authorize

// ==================== 单 audience（标准 OAuth2 form 请求）====================

// TokenRequest 标准 OAuth2 Token 请求（application/x-www-form-urlencoded）
type TokenRequest struct {
	GrantType    string `form:"grant_type" binding:"required,oneof=authorization_code refresh_token"`
	Code         string `form:"code"`          // authorization_code 时必填
	RedirectURI  string `form:"redirect_uri"`  // authorization_code 时必填
	ClientID     string `form:"client_id"`     // 必填
	CodeVerifier string `form:"code_verifier"` // PKCE 验证器
	RefreshToken string `form:"refresh_token"` // refresh_token grant 时必填
}

// TokenResponse 标准 OAuth2 Token 响应（单 audience）
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"` // 只有 offline_access 时返回
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"` // 实际授予的 scope
}

// ==================== 多 audience（JSON 请求）====================

// AudienceScope 单个 audience 的 scope 配置
type AudienceScope struct {
	Scope string `json:"scope"` // 不指定时默认 "openid"
}

// MultiAudienceTokenRequest 多 audience Token 请求（application/json，仅 authorization_code）
// refresh_token 场景下每个 audience 独立刷新，走单 audience 的 TokenRequest
type MultiAudienceTokenRequest struct {
	GrantType    string                    `json:"grant_type" binding:"required,oneof=authorization_code"`
	Code         string                    `json:"code" binding:"required"`
	RedirectURI  string                    `json:"redirect_uri,omitempty"`
	ClientID     string                    `json:"client_id" binding:"required"`
	CodeVerifier string                    `json:"code_verifier,omitempty"`
	Audiences    map[string]*AudienceScope `json:"audiences,omitempty"` // 可选，优先使用授权阶段存储在 flow 中的 audiences
}

// GetScope 获取 audience 的 scope，未指定时默认 "openid"
func (a *AudienceScope) GetScope() string {
	if a == nil || a.Scope == "" {
		return ScopeOpenID
	}
	return a.Scope
}

// MultiAudienceTokenResponse 多 audience Token 响应
// key 为 audience（service_id），value 为该 audience 的 token 信息
type MultiAudienceTokenResponse map[string]*TokenResponse

// ==================== 常量 ====================

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
