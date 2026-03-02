package aegis

import "errors"

// ==================== 常量 ====================

const (
	HeaderAuthorization = "Authorization" // Authorization 请求头
	BearerPrefix        = "Bearer "       // Bearer Token 前缀

	// Query 参数
	QueryClientID = "client_id" // Client ID 查询参数

	// Gin Context Key
	ContextKeyUser = "user" // 用户 Token 在 Gin Context 中的 key

	// Cookie
	AuthSessionCookie = "aegis-session" // Auth 会话 Cookie 名称
)

// ==================== 哨兵错误 ====================

// errIdentifiedUser 内部哨兵错误：resolveUser 识别到已有用户，需前端确认关联
var errIdentifiedUser = errors.New("identified existing user")
