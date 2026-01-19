package auth

import (
	"fmt"
	"time"
)

// Domain 用户域
type Domain string

const (
	DomainCIAM Domain = "ciam" // Customer Identity（C 端用户）
	DomainPIAM Domain = "piam" // Partner/Employee Identity（B 端用户）
)

// IDP 身份提供方
type IDP string

const (
	// CIAM 域
	IDPWechatMP IDP = "wechat:mp" // 微信小程序
	IDPTTMP     IDP = "tt:mp"     // 抖音小程序
	IDPAlipayMP IDP = "alipay:mp" // 支付宝小程序

	// PIAM 域
	IDPWecom  IDP = "wecom"  // 企业微信
	IDPGithub IDP = "github" // GitHub
	IDPGoogle IDP = "google" // Google
)

// GetDomain 获取 IDP 所属域
func (i IDP) GetDomain() Domain {
	switch i {
	case IDPWecom, IDPGithub, IDPGoogle:
		return DomainPIAM
	default:
		return DomainCIAM
	}
}

// SupportsAutoCreate 是否支持自动创建用户
func (i IDP) SupportsAutoCreate() bool {
	switch i {
	case IDPWechatMP, IDPTTMP, IDPAlipayMP:
		return true // C 端都支持
	default:
		return false // B 端需要预先配置
	}
}

// GrantType 授权类型
type GrantType string

const (
	GrantTypeAuthorizationCode GrantType = "authorization_code"
	GrantTypeRefreshToken      GrantType = "refresh_token"
)

// CodeChallengeMethod PKCE 验证方法
type CodeChallengeMethod string

const (
	CodeChallengeMethodS256  CodeChallengeMethod = "S256"
	CodeChallengeMethodPlain CodeChallengeMethod = "plain"
)

// ============= Request/Response =============

// AuthorizeRequest 授权请求
type AuthorizeRequest struct {
	ClientID            string              `json:"client_id" binding:"required"`
	RedirectURI         string              `json:"redirect_uri" binding:"required"`
	CodeChallenge       string              `json:"code_challenge" binding:"required"`
	CodeChallengeMethod CodeChallengeMethod `json:"code_challenge_method" binding:"required,oneof=S256 plain"`
	State               string              `json:"state"`
	Scope               string              `json:"scope"`
}

// AuthorizeResponse 授权响应
type AuthorizeResponse struct {
	SessionID string `json:"session_id"`
}

// LoginRequest 登录请求
type LoginRequest struct {
	IDP  IDP    `json:"idp" binding:"required"`
	Code string `json:"code" binding:"required"` // IDP 返回的授权码
}

// LoginResponse 登录响应
type LoginResponse struct {
	Code        string `json:"code"`                   // 授权码
	RedirectURI string `json:"redirect_uri,omitempty"` // 重定向 URI（带 code 和 state）
}

// TokenRequest Token 请求
type TokenRequest struct {
	GrantType    GrantType `form:"grant_type" binding:"required,oneof=authorization_code refresh_token"`
	Code         string    `form:"code"`          // authorization_code 时必填
	RedirectURI  string    `form:"redirect_uri"`  // authorization_code 时必填
	ClientID     string    `form:"client_id"`     // 必填
	CodeVerifier string    `form:"code_verifier"` // PKCE 验证器
	RefreshToken string    `form:"refresh_token"` // refresh_token grant 时必填
}

// TokenResponse Token 响应
type TokenResponse struct {
	AccessToken  string `json:"access_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"` // C 端用户使用
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

// RevokeRequest 撤销请求
type RevokeRequest struct {
	Token    string `form:"token" binding:"required"`
	ClientID string `form:"client_id"`
}

// UserInfoResponse 用户信息响应
type UserInfoResponse struct {
	Sub      string `json:"sub"`                 // 用户 ID
	Name     string `json:"name,omitempty"`      // 昵称
	Picture  string `json:"picture,omitempty"`   // 头像
	Phone    string `json:"phone,omitempty"`     // 手机号（脱敏）
	Domain   Domain `json:"domain"`              // 所属域
}

// UpdateUserInfoRequest 更新用户信息请求
type UpdateUserInfoRequest struct {
	Name    string `json:"name" binding:"omitempty,max=64"`
	Picture string `json:"picture" binding:"omitempty,max=512"`
}

// ============= Error =============

// Error OAuth2 错误
type Error struct {
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

func (e *Error) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("%s: %s", e.Code, e.Description)
	}
	return e.Code
}

// 标准错误码
const (
	ErrInvalidRequest       = "invalid_request"
	ErrUnauthorizedClient   = "unauthorized_client"
	ErrAccessDenied         = "access_denied"
	ErrInvalidClient        = "invalid_client"
	ErrInvalidGrant         = "invalid_grant"
	ErrUnsupportedGrantType = "unsupported_grant_type"
	ErrInvalidToken         = "invalid_token"
	ErrServerError          = "server_error"
)

// NewError 创建错误
func NewError(code, description string) *Error {
	return &Error{Code: code, Description: description}
}

// ============= Internal Types =============

// Session 认证会话
type Session struct {
	ID                  string              `json:"id"`
	ClientID            string              `json:"client_id"`
	RedirectURI         string              `json:"redirect_uri"`
	CodeChallenge       string              `json:"code_challenge"`
	CodeChallengeMethod CodeChallengeMethod `json:"code_challenge_method"`
	State               string              `json:"state"`
	Scope               string              `json:"scope"`
	CreatedAt           time.Time           `json:"created_at"`
	ExpiresAt           time.Time           `json:"expires_at"`

	// 登录后填充
	UserID string `json:"user_id,omitempty"`
	IDP    IDP    `json:"idp,omitempty"`
}

// AuthorizationCode 授权码
type AuthorizationCode struct {
	Code                string    `json:"code"`
	ClientID            string    `json:"client_id"`
	RedirectURI         string    `json:"redirect_uri"`
	CodeChallenge       string    `json:"code_challenge"`
	CodeChallengeMethod string    `json:"code_challenge_method"`
	Scope               string    `json:"scope"`
	UserID              string    `json:"user_id"`
	CreatedAt           time.Time `json:"created_at"`
	ExpiresAt           time.Time `json:"expires_at"`
	Used                bool      `json:"used"`
}

// Identity Token 中的用户身份（用于 Access Token 的 sub）
type Identity struct {
	UserID string `json:"sub"`
	Domain Domain `json:"domain"`
}

// GetOpenID 兼容旧接口，返回用户 ID
func (i *Identity) GetOpenID() string {
	return i.UserID
}

// OpenID 兼容旧接口，返回用户 ID
func (i *Identity) OpenID() string {
	return i.UserID
}
