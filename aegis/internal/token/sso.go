package token

import (
	"fmt"
	"time"

	"aidanwoods.dev/go-paseto"

	pkgtoken "github.com/heliannuuthus/helios/pkg/aegis/token"
)

// SSO Token 常量
const (
	SSOIssuer   = "aegis"          // SSO Token 签发者
	SSOAudience = "aegis"          // SSO Token 目标受众
	TokenTypeSSO = TokenType("sso") // SSO Token 类型标识
)

// SSOToken SSO 会话令牌
// 仅 Aegis 内部使用，不对外暴露
// Claims 明文（签名保护），用户身份加密存储在 footer 中
//
// 设计说明：
//   - 不含 cli（不绑定具体应用）
//   - 不含 scope（不代表授权，仅代表认证）
//   - iss = aud = "aegis"（自签发自验证）
//   - footer 为 domain→openID 的平铺映射，如 {"consumer":"openid_xxx","platform":"openid_yyy"}
//     每个域下的 openID 是该域中 t_user.openid（域隔离的用户标识）
type SSOToken struct {
	pkgtoken.Claims                // 内嵌基础 Claims
	identities      map[string]string // domain → openID（从 footer 解密获取）
}

// ==================== 构建 ====================

// SSOTokenBuilder SSO Token 构建器
type SSOTokenBuilder struct {
	issuer     string
	expiresIn  time.Duration
	identities map[string]string
}

// NewSSOTokenBuilder 创建 SSO Token 构建器
func NewSSOTokenBuilder() *SSOTokenBuilder {
	return &SSOTokenBuilder{
		issuer:     SSOIssuer,
		identities: make(map[string]string),
	}
}

// ExpiresIn 设置过期时间
func (b *SSOTokenBuilder) ExpiresIn(d time.Duration) *SSOTokenBuilder {
	b.expiresIn = d
	return b
}

// Identity 添加一条域身份
func (b *SSOTokenBuilder) Identity(domain, openID string) *SSOTokenBuilder {
	b.identities[domain] = openID
	return b
}

// Identities 批量设置域身份映射
func (b *SSOTokenBuilder) Identities(identities map[string]string) *SSOTokenBuilder {
	for domain, openID := range identities {
		b.identities[domain] = openID
	}
	return b
}

// Build 构建 SSOToken
func (b *SSOTokenBuilder) Build() *SSOToken {
	cp := make(map[string]string, len(b.identities))
	for k, v := range b.identities {
		cp[k] = v
	}

	claims := pkgtoken.NewClaimsBuilder().
		Issuer(SSOIssuer).
		Audience(SSOAudience).
		ExpiresIn(b.expiresIn).
		BuildClaims()

	return &SSOToken{
		Claims:     claims,
		identities: cp,
	}
}

// ==================== PASETO 构建 ====================

// BuildPaseto 构建 PASETO Token（不含签名和 footer）
func (s *SSOToken) BuildPaseto() (*paseto.Token, error) {
	t := paseto.NewToken()
	if err := s.SetStandardClaims(&t); err != nil {
		return nil, fmt.Errorf("set standard claims: %w", err)
	}
	return &t, nil
}

// ==================== 解析 ====================

// ParseSSOToken 从 PASETO Token 解析 SSOToken（仅解析 claims，footer 由 service 层解密后填充）
func ParseSSOToken(pasetoToken *paseto.Token) (*SSOToken, error) {
	claims, err := pkgtoken.ParseClaims(pasetoToken)
	if err != nil {
		return nil, fmt.Errorf("parse claims: %w", err)
	}

	return &SSOToken{
		Claims: claims,
	}, nil
}

// ==================== Footer 数据 ====================

// GetFooterData 获取用于 footer 加密的数据
// 返回 domain→openID 的平铺 map，直接序列化为 JSON
func (s *SSOToken) GetFooterData() map[string]string {
	if len(s.identities) == 0 {
		return nil
	}
	cp := make(map[string]string, len(s.identities))
	for k, v := range s.identities {
		cp[k] = v
	}
	return cp
}

// SetIdentities 设置域身份映射（从解密的 footer 填充）
func (s *SSOToken) SetIdentities(identities map[string]string) {
	s.identities = identities
}

// HasUser 检查是否有任何域身份
func (s *SSOToken) HasUser() bool {
	return len(s.identities) > 0
}

// ==================== Getter ====================

// GetOpenID 返回指定域下的 OpenID，不存在则返回空字符串
func (s *SSOToken) GetOpenID(domain string) string {
	if s.identities == nil {
		return ""
	}
	return s.identities[domain]
}

// GetIdentities 返回全部域身份映射（防御性拷贝）
func (s *SSOToken) GetIdentities() map[string]string {
	if s.identities == nil {
		return nil
	}
	cp := make(map[string]string, len(s.identities))
	for k, v := range s.identities {
		cp[k] = v
	}
	return cp
}
