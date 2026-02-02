package idp

// IDP 类型常量
const (
	// CIAM 域 - 小程序
	TypeWechatMP = "wechat:mp" // 微信小程序
	TypeTTMP     = "tt:mp"     // 抖音小程序
	TypeAlipayMP = "alipay:mp" // 支付宝小程序

	// CIAM 域 - Web 授权
	TypeWechatWeb = "wechat:web" // 微信网页授权
	TypeAlipayWeb = "alipay:web" // 支付宝网页授权
	TypeTTWeb     = "tt:web"     // 抖音网页授权

	// PIAM 域
	TypeWecom  = "wecom"  // 企业微信
	TypeGithub = "github" // GitHub
	TypeGoogle = "google" // Google
	TypeEmail  = "email"  // 邮箱验证码（PIAM 专用）
)

// Domain 用户域
type Domain string

const (
	DomainCIAM Domain = "ciam" // Customer Identity（C 端用户）
	DomainPIAM Domain = "piam" // Partner/Employee Identity（B 端用户）
)

// GetDomain 获取 IDP 所属域
func GetDomain(idpType string) Domain {
	switch idpType {
	case TypeWecom, TypeGithub, TypeGoogle, TypeEmail:
		return DomainPIAM
	default:
		return DomainCIAM
	}
}

// SupportsAutoCreate 是否支持自动创建用户
// CIAM 域的社交登录允许自动创建，PIAM 域需要预先创建用户（会员制）
func SupportsAutoCreate(idpType string) bool {
	switch idpType {
	case TypeWechatMP, TypeTTMP, TypeAlipayMP, TypeWechatWeb, TypeAlipayWeb, TypeTTWeb:
		return true // C 端社交登录都支持自动创建
	default:
		return false // PIAM 域（邮箱/企业微信/GitHub/Google）需要预先配置用户
	}
}

// RequiresVerifiedEmail 是否需要邮箱已验证
func RequiresVerifiedEmail(idpType string) bool {
	return idpType == TypeEmail
}
