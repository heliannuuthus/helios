package idp

import "github.com/heliannuuthus/helios/internal/config"

// IDP 类型常量
const (
	// CIAM 域 - 小程序
	TypeWechatMP = "wechat-mp" // 微信小程序
	TypeTTMP     = "tt-mp"     // 抖音小程序
	TypeAlipayMP = "alipay-mp" // 支付宝小程序

	// CIAM 域 - Web 授权
	TypeWechatWeb = "wechat-web" // 微信网页授权
	TypeAlipayWeb = "alipay-web" // 支付宝网页授权
	TypeTTWeb     = "tt-web"     // 抖音网页授权

	// CIAM 域 - 账号密码
	TypeUser = "user" // C 端用户账号密码登录

	// PIAM 域
	TypeWecom  = "wecom"  // 企业微信
	TypeGithub = "github" // GitHub
	TypeGoogle = "google" // Google
	TypeOper   = "oper"   // 运营人员账号密码登录

	// 通用 - Passkey（无密码登录）
	TypePasskey = "passkey" // Passkey/WebAuthn 无密码登录

	// 系统 - 全局身份
	TypeGlobal = "global" // 全局身份（每个域一个，t_openid 作为该域下的 sub）
)

// Domain 用户域
type Domain string

const (
	DomainCIAM Domain = "ciam" // Customer Identity（C 端用户）
	DomainPIAM Domain = "piam" // Partner/Employee Identity（B 端用户）
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

// RequiresEmailForBinding 是否需要邮箱来绑定身份（用于 PIAM 域的 OAuth 登录）
// GitHub/Google 等需要通过邮箱来查找/绑定 oper 身份
func RequiresEmailForBinding(idpType string) bool {
	return idpType == TypeGithub || idpType == TypeGoogle
}
