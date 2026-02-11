package webauthn

// WebAuthn 操作类型常量
const (
	OperationRegistration      = "registration"       // 注册凭证
	OperationLogin             = "login"              // 已知用户登录
	OperationDiscoverableLogin = "discoverable_login" // 无用户名发现式登录
)
