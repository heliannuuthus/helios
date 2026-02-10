package aegis

import (
	"github.com/heliannuuthus/helios/internal/aegis/token"
)

// ============= Type Aliases =============

// Token Token 接口（类型别名，实际定义在 token 包）
type Token = token.Token

// AsUAT 类型断言助手函数（类型别名）
var AsUAT = token.AsUAT

// GetOpenIDFromToken 从 Token 获取用户对外标识（主身份 t_openid）
func GetOpenIDFromToken(t Token) string {
	if uat, ok := AsUAT(t); ok && uat.HasUser() {
		return uat.GetOpenID()
	}
	return ""
}

// GetInternalUIDFromToken 从 Token 获取用户内部 ID（t_user.openid，用于内部查询）
func GetInternalUIDFromToken(t Token) string {
	if uat, ok := AsUAT(t); ok && uat.HasUser() {
		return uat.GetInternalUID()
	}
	return ""
}

// LoginRequest 登录请求
type LoginRequest struct {
	// 必填：身份标识
	Connection string `json:"connection" binding:"required"` // 身份标识（user, oper, github, wechat...）

	// 可选：认证方式（用于同一 connection 支持多种策略的情况）
	Strategy string `json:"strategy,omitempty"` // 认证方式（user/oper: password/webauthn; captcha: turnstile; 其余忽略）

	// 身份主体（用户名/邮箱/手机号/OpenID...）
	Principal string `json:"principal,omitempty"`

	// 凭证证明（any 类型，由各 authenticator 自行解析）
	// 可能是 string（password/OTP/captcha token）或复杂对象（OAuth 回调数据等）
	Proof any `json:"proof,omitempty"`
}

// LoginResponse 登录响应
type LoginResponse struct {
	Code        string `json:"code,omitempty"`         // 授权码
	RedirectURI string `json:"redirect_uri,omitempty"` // 重定向 URI
}

// RevokeRequest 撤销请求
type RevokeRequest struct {
	Token    string `form:"token" binding:"required"`
	ClientID string `form:"client_id"`
}

// CheckRequest 关系检查请求
// 使用 CAT 认证，检查指定主体是否具有指定的关系权限
type CheckRequest struct {
	SubjectType string `json:"subject_type" binding:"required"` // 主体类型：user / client
	SubjectID   string `json:"subject_id" binding:"required"`   // 主体 ID：OpenID / ClientID
	Relation    string `json:"relation" binding:"required"`     // 关系类型（如 admin, editor, viewer）
	ObjectType  string `json:"object_type"`                     // 资源类型（如 recipe, user, *）
	ObjectID    string `json:"object_id"`                       // 资源 ID（如 recipe_123, *）
}

// CheckResponse 关系检查响应
type CheckResponse struct {
	Permitted bool   `json:"permitted"`         // 是否有权限
	Error     string `json:"error,omitempty"`   // 错误码
	Message   string `json:"message,omitempty"` // 错误信息
}
