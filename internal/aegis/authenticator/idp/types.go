package idp

import "github.com/heliannuuthus/helios/internal/config"

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

	// CIAM 域 - 账号密码
	TypeUser = "user" // C 端用户账号密码登录

	// PIAM 域
	TypeWecom  = "wecom"  // 企业微信
	TypeGithub = "github" // GitHub
	TypeGoogle = "google" // Google
	TypeOper   = "oper"   // 运营人员账号密码登录

	// 通用 - Passkey（无密码登录）
	TypePasskey = "passkey" // Passkey/WebAuthn 无密码登录
)

// Domain 用户域
type Domain string

const (
	DomainCIAM Domain = "ciam" // Customer Identity（C 端用户）
	DomainPIAM Domain = "piam" // Partner/Employee Identity（B 端用户）
)

// IdentityType 身份类型
type IdentityType string

const (
	IdentityUser IdentityType = "user" // C 端用户
	IdentityOper IdentityType = "oper" // B 端运营人员
)

// GetDomain 获取 IDP 所属域（基于配置）
func GetDomain(idpType string) Domain {
	cfg := config.Aegis()

	// 检查是否在 PIAM IDP 列表中
	piamIDPs := cfg.GetStringSlice("identity.piam-idps")
	for _, idp := range piamIDPs {
		if idp == idpType {
			return DomainPIAM
		}
	}

	// 检查是否在 CIAM IDP 列表中
	ciamIDPs := cfg.GetStringSlice("identity.ciam-idps")
	for _, idp := range ciamIDPs {
		if idp == idpType {
			return DomainCIAM
		}
	}

	// 默认返回 CIAM
	return DomainCIAM
}

// GetIdentityType 获取 IDP 对应的身份类型
func GetIdentityType(idpType string) IdentityType {
	domain := GetDomain(idpType)
	if domain == DomainPIAM {
		return IdentityOper
	}
	return IdentityUser
}

// SupportsAutoCreate 是否支持自动创建用户
// 默认允许自动创建，所有域的 IDP 都支持首次登录自动注册
func SupportsAutoCreate(_ string) bool {
	return true
}

// IsIDPAllowedForDomain 检查 IDP 是否允许用于指定域
func IsIDPAllowedForDomain(idpType string, domain Domain) bool {
	cfg := config.Aegis()

	var allowedIDPs []string
	if domain == DomainCIAM {
		allowedIDPs = cfg.GetStringSlice("identity.ciam-idps")
	} else {
		allowedIDPs = cfg.GetStringSlice("identity.piam-idps")
	}

	for _, idp := range allowedIDPs {
		if idp == idpType {
			return true
		}
	}
	return false
}

// AreIdentitiesExclusive 检查两个身份类型是否互斥
func AreIdentitiesExclusive(identity1, identity2 IdentityType) bool {
	cfg := config.Aegis()
	exclusiveList := cfg.GetStringSlice("identity.identity-exclusive")

	// 检查两个身份是否都在互斥列表中
	found1, found2 := false, false
	for _, id := range exclusiveList {
		if IdentityType(id) == identity1 {
			found1 = true
		}
		if IdentityType(id) == identity2 {
			found2 = true
		}
	}

	return found1 && found2
}

// RequiresEmailForBinding 是否需要邮箱来绑定身份（用于 PIAM 域的 OAuth 登录）
// GitHub/Google 等需要通过邮箱来查找/绑定 oper 身份
func RequiresEmailForBinding(idpType string) bool {
	return idpType == TypeGithub || idpType == TypeGoogle
}
