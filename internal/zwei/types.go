package zwei

import "fmt"

// AuthorizeRequest OIDC 风格的授权请求
type AuthorizeRequest struct {
	ClientID            string `json:"client_id" binding:"required"`
	RedirectURI         string `json:"redirect_uri" binding:"required"`
	ResponseType        string `json:"response_type" binding:"required,oneof=code"`
	Scope               string `json:"scope,omitempty"`
	State               string `json:"state,omitempty"`
	CodeChallenge       string `json:"code_challenge" binding:"required"`
	CodeChallengeMethod string `json:"code_challenge_method" binding:"required,oneof=S256 plain"`
	CodeVerifier        string `json:"code_verifier" binding:"required"` // PKCE verifier
	Code                string `json:"code" binding:"required"`          // 小程序登录 code
	Connection          string `json:"connection" binding:"required"`    // 连接类型：wechat:mp, tt:mp, alipay:mp
}

// AuthorizeResponse OIDC 风格的授权响应
type AuthorizeResponse struct {
	Code  string `json:"code,omitempty"`  // 授权码（如果 response_type=code）
	State string `json:"state,omitempty"`  // 原样返回 state
}

// TokenResponse OIDC 风格的 token 响应
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope,omitempty"`
}

// OAuth2Error OAuth2 错误响应
type OAuth2Error struct {
	ErrorCode        string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorURI         string `json:"error_uri,omitempty"`
	State            string `json:"state,omitempty"`
}

// Error 实现 error 接口
func (e *OAuth2Error) Error() string {
	if e.ErrorDescription != "" {
		return fmt.Sprintf("%s: %s", e.ErrorCode, e.ErrorDescription)
	}
	return e.ErrorCode
}
