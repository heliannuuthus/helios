package aegis

import (
	"fmt"
	"strings"

	"github.com/heliannuuthus/helios/aegis/internal/token"
)

// ============= Type Aliases =============

// Token Token 接口（类型别名，实际定义在 token 包）
type Token = token.Token

// GetOpenIDFromToken 从 Token 获取用户标识（t_user.openid）
func GetOpenIDFromToken(t Token) string {
	if uat, ok := t.(*token.UserAccessToken); ok && uat.HasUser() {
		return uat.GetOpenID()
	}
	return ""
}

// LoginRequest 登录请求
type LoginRequest struct {
	// 必填：身份标识
	Connection string `json:"connection" binding:"required"` // 身份标识（user, staff, github, wechat...）

	// 可选：认证方式（用于同一 connection 支持多种策略的情况）
	Strategy string `json:"strategy,omitempty"` // 认证方式（user/staff: password/webauthn; captcha: turnstile; 其余忽略）

	// 身份主体（用户名/邮箱/手机号/OpenID...）
	Principal string `json:"principal,omitempty"`

	// 凭证证明（any 类型，由各 authenticator 自行解析）
	// 可能是 string（password/OTP/captcha token）或复杂对象（OAuth 回调数据等）
	Proof any `json:"proof,omitempty"`
}

// String 返回脱敏的日志表示
func (r LoginRequest) String() string {
	proofHint := "<nil>"
	if r.Proof != nil {
		switch v := r.Proof.(type) {
		case string:
			if len(v) > 0 {
				proofHint = fmt.Sprintf("<string:%d>", len(v))
			}
		default:
			proofHint = fmt.Sprintf("<%T>", v)
		}
	}
	return fmt.Sprintf("{Connection: %s, Strategy: %s, Principal: %s, Proof: %s}",
		r.Connection, r.Strategy, maskPrincipal(r.Principal), proofHint)
}

func maskPrincipal(s string) string {
	if s == "" {
		return ""
	}
	if idx := strings.Index(s, "@"); idx > 0 {
		prefix := s[:min(3, idx)]
		return prefix + "***" + s[idx:]
	}
	if len(s) <= 3 {
		return s + "***"
	}
	return s[:3] + "***"
}

// LoginResponse 登录响应
type LoginResponse struct {
	Location string `json:"location"` // 重定向地址（携带 code 和 state）
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

// IdentifyResponse 识别到已有用户的响应
type IdentifyResponse struct {
	Connection string          `json:"connection"`     // 当前登录的 IDP（github/google 等）
	User       *IdentifiedUser `json:"user,omitempty"` // 匹配到的已有用户
}

// IdentifiedUser 被识别到的已有用户摘要
type IdentifiedUser struct {
	Nickname string `json:"nickname,omitempty"` // 昵称
	Picture  string `json:"picture,omitempty"`  // 头像 URL
}

// ConfirmIdentifyRequest 确认/取消关联请求
type ConfirmIdentifyRequest struct {
	Confirm bool `json:"confirm"` // true=确认关联，false=取消
}
