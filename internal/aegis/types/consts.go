package types

// ==================== Connection 标识 ====================

const (
	ConnOper    = "oper"    // 运营人员登录
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
	ChallengeDataEmail          = "email"           // 邮箱地址
	ChallengeDataMaskedEmail    = "masked_email"    // 脱敏邮箱
	ChallengeDataUserID         = "user_id"         // 用户 ID（TOTP）
	ChallengeDataSiteKey        = "site_key"        // Captcha 站点密钥
	ChallengeDataPendingCaptcha = "pending_captcha" // 是否需要 captcha 前置验证
	ChallengeDataNext           = "next"            // 下一步操作类型
	ChallengeDataSession        = "session"         // WebAuthn session 数据
	ChallengeDataOperation      = "operation"       // WebAuthn 操作类型
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
