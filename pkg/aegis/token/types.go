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

// 验证错误
var (
	ErrUnsupportedAudience = errors.New("unsupported audience")
	ErrTokenExpired        = errors.New("token expired")
	ErrInvalidSignature    = errors.New("invalid signature")
	ErrMissingClaims       = errors.New("missing required claims")
)

// AccessToken 定义 token 构建接口
// 各种类型的 token（ClientAccessToken, ServiceAccessToken, UserAccessToken）都实现此接口
type AccessToken interface {
	// Build 构建 PASETO Token（不包含签名）
	Build() (*paseto.Token, error)

	// 标准字段 getter
	GetIssuer() string
	GetClientID() string
	GetAudience() string
	ExpiresIn() time.Duration
	GetJTI() string
}

// Claims 所有 Token 的公共基础结构
// 包含 PASETO Token 的标准字段
type Claims struct {
	Issuer    string        // iss - 签发者
	ClientID  string        // cli - 应用 ID
	Audience  string        // aud - 服务/目标受众
	ExpiresIn time.Duration // 有效期（构建时使用）
	IssuedAt  time.Time     // iat - 签发时间（解析后填充）
	ExpiresAt time.Time     // exp - 过期时间（解析后填充）
	JTI       string        // jti - Token ID
}

// NewClaims 创建基础 Claims（用于签发）
func NewClaims(issuer, clientID, audience string, expiresIn time.Duration) Claims {
	return Claims{
		Issuer:    issuer,
		ClientID:  clientID,
		Audience:  audience,
		ExpiresIn: expiresIn,
		JTI:       generateJTI(),
	}
}

// ParseClaims 从 PASETO Token 解析基础字段（用于验证后）
func ParseClaims(pasetoToken *paseto.Token) (Claims, error) {
	issuer, err := pasetoToken.GetIssuer()
	if err != nil {
		return Claims{}, fmt.Errorf("get issuer: %w", err)
	}

	audience, err := pasetoToken.GetAudience()
	if err != nil {
		return Claims{}, fmt.Errorf("get audience: %w", err)
	}

	issuedAt, err := pasetoToken.GetIssuedAt()
	if err != nil {
		return Claims{}, fmt.Errorf("get issued_at: %w", err)
	}

	expiresAt, err := pasetoToken.GetExpiration()
	if err != nil {
		return Claims{}, fmt.Errorf("get expiration: %w", err)
	}

	jti, err := pasetoToken.GetJti()
	if err != nil {
		return Claims{}, fmt.Errorf("get jti: %w", err)
	}

	var clientID string
	if err := pasetoToken.Get("cli", &clientID); err != nil {
		// cli 是自定义字段，可能不存在（如 CAT 使用 sub）
		clientID = ""
	}

	return Claims{
		Issuer:    issuer,
		ClientID:  clientID,
		Audience:  audience,
		IssuedAt:  issuedAt,
		ExpiresAt: expiresAt,
		JTI:       jti,
	}, nil
}

// SetStandardClaims 设置标准 claims 到 PASETO Token
func (c *Claims) SetStandardClaims(token *paseto.Token) error {
	now := time.Now()
	token.SetIssuer(c.Issuer)
	token.SetAudience(c.Audience)
	token.SetIssuedAt(now)
	token.SetExpiration(now.Add(c.ExpiresIn))
	token.SetNotBefore(now)
	token.SetJti(c.JTI)
	if err := token.Set("cli", c.ClientID); err != nil {
		return fmt.Errorf("set cli: %w", err)
	}
	return nil
}

// GetIssuer 返回签发者
func (c *Claims) GetIssuer() string {
	return c.Issuer
}

// GetClientID 返回应用 ID
func (c *Claims) GetClientID() string {
	return c.ClientID
}

// GetAudience 返回服务 ID
func (c *Claims) GetAudience() string {
	return c.Audience
}

// GetExpiresIn 返回有效期（构建时设置的相对时间）
func (c *Claims) GetExpiresIn() time.Duration {
	return c.ExpiresIn
}

// GetIssuedAt 返回签发时间（解析后填充）
func (c *Claims) GetIssuedAt() time.Time {
	return c.IssuedAt
}

// GetExpiresAt 返回过期时间（解析后填充）
func (c *Claims) GetExpiresAt() time.Time {
	return c.ExpiresAt
}

// GetJTI 返回 Token ID
func (c *Claims) GetJTI() string {
	return c.JTI
}

// generateJTI 生成 Token ID
func generateJTI() string {
	jtiBytes := make([]byte, 16)
	if _, err := rand.Read(jtiBytes); err != nil {
		// 极端情况：使用时间戳作为后备
		return hex.EncodeToString([]byte(time.Now().String()))
	}
	return hex.EncodeToString(jtiBytes)
}

// UserInfo 用户身份信息
// 用于：1) 加密到 footer 中  2) 解密后填充到 UserAccessToken
type UserInfo struct {
	Subject  string `json:"sub,omitempty"`      // 用户 OpenID
	Nickname string `json:"nickname,omitempty"` // 昵称
	Picture  string `json:"picture,omitempty"`  // 头像
	Email    string `json:"email,omitempty"`    // 邮箱
	Phone    string `json:"phone,omitempty"`    // 手机号
}

// GetOpenID 返回用户 OpenID（即 Subject）
func (u *UserInfo) GetOpenID() string {
	return u.Subject
}

// HasScope 检查 scope 字符串是否包含某个 scope
func HasScope(scopeStr, scope string) bool {
	scopes := strings.Fields(scopeStr)
	for _, s := range scopes {
		if s == scope {
			return true
		}
	}
	return false
}
