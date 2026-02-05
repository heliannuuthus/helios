package token

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"aidanwoods.dev/go-paseto"
)

// ==================== 错误定义 ====================

var (
	ErrUnsupportedAudience = errors.New("unsupported audience")
	ErrTokenExpired        = errors.New("token expired")
	ErrInvalidSignature    = errors.New("invalid signature")
	ErrMissingClaims       = errors.New("missing required claims")
	ErrUnsupportedToken    = errors.New("unsupported token type")
)

// ==================== Token 接口 ====================

// Token 所有凭证的统一只读接口
// 用于解析后返回，业务方通过类型断言获取具体类型
type Token interface {
	// Type 返回凭证类型标识
	Type() TokenType

	// 基础 Claims Getter 方法
	GetIssuer() string
	GetClientID() string
	GetAudience() string
	GetSubject() string
	GetIssuedAt() time.Time
	GetExpiresAt() time.Time
	GetJTI() string

	// IsExpired 检查是否已过期
	IsExpired() bool
}

// tokenBuilder 内部签发接口
type tokenBuilder interface {
	Token
	build() (*paseto.Token, error)
}

// Build 构建 PASETO Token（供签发使用）
// 传入的 Token 必须是可签发的具体类型（UAT/SAT/CAT/ChallengeToken）
func Build(t Token) (*paseto.Token, error) {
	if builder, ok := t.(tokenBuilder); ok {
		return builder.build()
	}
	return nil, fmt.Errorf("%w: token does not support building", ErrUnsupportedToken)
}

// TokenType 凭证类型
type TokenType string

const (
	TokenTypeCAT       TokenType = "cat"       // Client Access Token - 客户端自签发
	TokenTypeUAT       TokenType = "uat"       // User Access Token - 用户访问令牌
	TokenTypeSAT       TokenType = "sat"       // Service Access Token - M2M 服务令牌
	TokenTypeChallenge TokenType = "challenge" // Challenge Token - 验证挑战令牌
)

// ==================== claims 内部基础结构 ====================

// claims 用于构建 Token 的内部基础结构（不对外暴露）
type claims struct {
	Issuer    string        // iss - 签发者
	ClientID  string        // cli - 应用 ID
	Audience  string        // aud - 服务/目标受众
	Subject   string        // sub - 主体（可选，取决于 Token 类型）
	ExpiresIn time.Duration // 有效期（构建时使用）
	IssuedAt  time.Time     // iat - 签发时间（解析后填充）
	ExpiresAt time.Time     // exp - 过期时间（解析后填充）
	JTI       string        // jti - Token ID
}

// newClaims 创建基础 claims（用于签发）
func newClaims(issuer, clientID, audience string, expiresIn time.Duration) claims {
	return claims{
		Issuer:    issuer,
		ClientID:  clientID,
		Audience:  audience,
		ExpiresIn: expiresIn,
		JTI:       generateJTI(),
	}
}

// parseClaims 从 PASETO Token 解析基础字段（用于验证后）
func parseClaims(pasetoToken *paseto.Token) (claims, error) {
	issuer, err := pasetoToken.GetIssuer()
	if err != nil {
		return claims{}, fmt.Errorf("get issuer: %w", err)
	}

	audience, err := pasetoToken.GetAudience()
	if err != nil {
		return claims{}, fmt.Errorf("get audience: %w", err)
	}

	issuedAt, err := pasetoToken.GetIssuedAt()
	if err != nil {
		return claims{}, fmt.Errorf("get issued_at: %w", err)
	}

	expiresAt, err := pasetoToken.GetExpiration()
	if err != nil {
		return claims{}, fmt.Errorf("get expiration: %w", err)
	}

	jti, err := pasetoToken.GetJti()
	if err != nil {
		return claims{}, fmt.Errorf("get jti: %w", err)
	}

	// cli 是自定义字段，可能不存在（如 CAT 使用 sub）
	var clientID string
	_ = pasetoToken.Get("cli", &clientID)

	// sub 是可选字段
	subject, _ := pasetoToken.GetSubject()

	return claims{
		Issuer:    issuer,
		ClientID:  clientID,
		Audience:  audience,
		Subject:   subject,
		IssuedAt:  issuedAt,
		ExpiresAt: expiresAt,
		JTI:       jti,
	}, nil
}

// setStandardClaims 设置标准 claims 到 PASETO Token
func (c *claims) setStandardClaims(token *paseto.Token) error {
	now := time.Now()
	token.SetIssuer(c.Issuer)
	token.SetAudience(c.Audience)
	token.SetIssuedAt(now)
	token.SetExpiration(now.Add(c.ExpiresIn))
	token.SetNotBefore(now)
	token.SetJti(c.JTI)

	if c.ClientID != "" {
		if err := token.Set("cli", c.ClientID); err != nil {
			return fmt.Errorf("set cli: %w", err)
		}
	}
	if c.Subject != "" {
		token.SetSubject(c.Subject)
	}
	return nil
}

// generateJTI 生成 Token ID
func generateJTI() string {
	jtiBytes := make([]byte, 16)
	if _, err := rand.Read(jtiBytes); err != nil {
		return hex.EncodeToString([]byte(time.Now().String()))
	}
	return hex.EncodeToString(jtiBytes)
}

// ==================== UserInfo ====================

// UserInfo 用户身份信息（UAT footer 加密存储）
type UserInfo struct {
	Subject  string `json:"sub,omitempty"`      // 用户 OpenID
	Nickname string `json:"nickname,omitempty"` // 昵称
	Picture  string `json:"picture,omitempty"`  // 头像
	Email    string `json:"email,omitempty"`    // 邮箱
	Phone    string `json:"phone,omitempty"`    // 手机号
}

// GetOpenID 返回用户 OpenID
func (u *UserInfo) GetOpenID() string { return u.Subject }

// ==================== 类型断言辅助函数 ====================

// AsCAT 将 Token 断言为 ClientAccessToken
func AsCAT(t Token) (*ClientAccessToken, bool) {
	cat, ok := t.(*ClientAccessToken)
	return cat, ok
}

// AsUAT 将 Token 断言为 UserAccessToken
func AsUAT(t Token) (*UserAccessToken, bool) {
	uat, ok := t.(*UserAccessToken)
	return uat, ok
}

// AsSAT 将 Token 断言为 ServiceAccessToken
func AsSAT(t Token) (*ServiceAccessToken, bool) {
	sat, ok := t.(*ServiceAccessToken)
	return sat, ok
}

// AsChallenge 将 Token 断言为 ChallengeToken
func AsChallenge(t Token) (*ChallengeToken, bool) {
	ct, ok := t.(*ChallengeToken)
	return ct, ok
}

// ==================== 辅助函数 ====================

// hasScope 检查 scope 字符串是否包含某个 scope
func hasScope(scopeStr, scope string) bool {
	for _, s := range strings.Fields(scopeStr) {
		if s == scope {
			return true
		}
	}
	return false
}

// parseScopeSet 解析 scope 字符串为集合
func parseScopeSet(scope string) map[string]bool {
	set := make(map[string]bool)
	for _, s := range strings.Fields(scope) {
		set[s] = true
	}
	return set
}

// UserInfoFromScope 根据 scope 构建用户信息
func UserInfoFromScope(openID, nickname, picture, email, phone, scope string) *UserInfo {
	info := &UserInfo{Subject: openID}
	scopeSet := parseScopeSet(scope)

	if scopeSet["profile"] {
		info.Nickname = nickname
		info.Picture = picture
	}
	if scopeSet["email"] {
		info.Email = email
	}
	if scopeSet["phone"] {
		info.Phone = phone
	}
	return info
}
