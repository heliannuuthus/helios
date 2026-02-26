// nolint:revive // This package name follows Go conventions for internal type packages.
package types

// ==================== Connection 类型 ====================

// ConnectionType 连接类型（idp/vchan/factor）
type ConnectionType string

const (
	ConnTypeIDP    ConnectionType = "idp"    // 身份提供商（github, google, user, staff, passkey...）
	ConnTypeVChan  ConnectionType = "vchan"  // 验证通道（captcha）
	ConnTypeFactor ConnectionType = "factor" // 认证因子（totp, email_otp, webauthn）
)

// ==================== Connection 标识 ====================

const (
	ConnStaff   = "staff"   // 平台人员登录
	ConnUser    = "user"    // C 端用户登录
	ConnPasskey = "passkey" // Passkey 无密码登录
	ConnCaptcha = "captcha" // 人机验证
	ConnGitHub  = "github"  // GitHub OAuth
	ConnGoogle  = "google"  // Google OAuth
)

// ==================== 认证策略 ====================

const (
	StrategyPassword = "password" // 密码认证
)

// ==================== Challenge Data Key ====================
// Challenge.Data map 中使用的 key

const (
	ChallengeDataSiteKey   = "site_key"  // Captcha 站点密钥
	ChallengeDataNext      = "next"      // 下一步操作类型
	ChallengeDataSession   = "session"   // WebAuthn session 数据
	ChallengeDataOperation = "operation" // WebAuthn 操作类型
)

// ==================== Rate Limit Key 前缀 ====================

const (
	RateLimitKeyPrefixCreate     = "rl:create:"    // Challenge 创建频率（channel 维度）
	RateLimitKeyPrefixCreateIP   = "rl:create:ip:" // Challenge 创建频率（IP 维度）
	RateLimitKeyPrefixVerifyFail = "rl:vfail:"     // 验证错误计数（channel 维度）
	RateLimitKeyPrefixLoginFail  = "rl:login:"     // 登录失败计数
)

// ==================== Subject Type ====================
// 关系检查中的主体类型

const (
	SubjectTypeUser = "user" // 用户
	SubjectTypeApp  = "app"  // 应用
)

// ==================== Cache Key 前缀 ====================

const (
	CacheKeyPrefixEmailOTP = "email_otp:" // 邮件验证码 cache key 前缀
)

// ==================== OAuth ====================

const (
	ResponseTypeCode = "code" // OAuth 授权码模式
)
