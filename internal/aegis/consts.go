package aegis

// ==================== HTTP 常量 ====================

const (
	HeaderAuthorization = "Authorization" // Authorization 请求头
	BearerPrefix        = "Bearer "       // Bearer Token 前缀

	// Query 参数
	QueryChallengeID = "challenge_id" // Challenge ID 查询参数
	QueryClientID    = "client_id"    // Client ID 查询参数

	// Gin Context Key
	ContextKeyUser = "user" // 用户 Token 在 Gin Context 中的 key
)
