package token

// Token Claim Key 常量
// PASETO Token 中自定义 claim 的 key
const (
	ClaimType        = "typ" // 业务类型（login / forget_password / bind_phone ...）
	ClaimChannelType = "ctp" // 渠道类型（email_otp / sms_otp / totp ...）
	ClaimCli         = "cli" // 应用 ID（Client ID）
	ClaimScope       = "scope"

	// UAT Scope 值
	ScopeProfile = "profile" // 用户基本信息
	ScopeEmail   = "email"   // 邮箱信息
	ScopePhone   = "phone"   // 手机号信息

	// UAT Footer Key
	FooterSub      = "sub"      // 用户标识
	FooterNickname = "nickname" // 用户昵称
	FooterPicture  = "picture"  // 用户头像
	FooterEmail    = "email"    // 用户邮箱
	FooterPhone    = "phone"    // 用户手机号

	// PASETO 标识
	PasetoVersion = "v4"     // PASETO 版本
	PasetoPurpose = "public" // PASETO 用途（公钥签名）

	// Token 类型
	TokenTypeBearer = "Bearer" // Bearer Token
)
