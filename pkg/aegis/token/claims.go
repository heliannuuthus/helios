package token

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"aidanwoods.dev/go-paseto"
)

// Claims 用于构建 Token 的基础结构
type Claims struct {
	Issuer    string        // iss - 签发者
	ClientID  string        // cli - 应用 ID
	Audience  string        // aud - 服务/目标受众
	Subject   string        // sub - 主体（可选，取决于 Token 类型）
	ExpiresIn time.Duration // 有效期（构建时使用）
	IssuedAt  time.Time     // iat - 签发时间（解析后填充）
	ExpiresAt time.Time     // exp - 过期时间（解析后填充）
	JTI       string        // jti - Token ID
}

// ==================== TokenTypeBuilder 接口 ====================

// TokenTypeBuilder Token 类型构建器接口
// 各 Token 类型实现此接口，用于 ClaimsBuilder.Build() 构建具体 Token
type TokenTypeBuilder interface {
	build(claims Claims) Token
}

// ==================== ClaimsBuilder ====================

// ClaimsBuilder Claims 构建器
type ClaimsBuilder struct {
	claims Claims
}

// NewClaimsBuilder 创建 Claims 构建器
func NewClaimsBuilder() *ClaimsBuilder {
	return &ClaimsBuilder{
		claims: Claims{
			JTI: generateJTI(),
		},
	}
}

// Issuer 设置签发者
func (b *ClaimsBuilder) Issuer(issuer string) *ClaimsBuilder {
	b.claims.Issuer = issuer
	return b
}

// ClientID 设置应用 ID
func (b *ClaimsBuilder) ClientID(clientID string) *ClaimsBuilder {
	b.claims.ClientID = clientID
	return b
}

// Audience 设置目标受众
func (b *ClaimsBuilder) Audience(audience string) *ClaimsBuilder {
	b.claims.Audience = audience
	return b
}

// Subject 设置主体
func (b *ClaimsBuilder) Subject(subject string) *ClaimsBuilder {
	b.claims.Subject = subject
	return b
}

// ExpiresIn 设置有效期
func (b *ClaimsBuilder) ExpiresIn(expiresIn time.Duration) *ClaimsBuilder {
	b.claims.ExpiresIn = expiresIn
	return b
}

// Build 使用 TokenTypeBuilder 构建具体 Token
func (b *ClaimsBuilder) Build(typeBuilder TokenTypeBuilder) Token {
	return typeBuilder.build(b.claims)
}

// BuildClaims 仅构建 Claims（不构建具体 Token）
func (b *ClaimsBuilder) BuildClaims() Claims {
	return b.claims
}

// ==================== 解析函数 ====================

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

	// clientID 是自定义字段，可能不存在，忽略错误
	var clientID string
	if err := pasetoToken.Get("cli", &clientID); err != nil {
		clientID = "" // 显式设置为空字符串
	}

	// subject 是可选字段，可能不存在
	subject, err := pasetoToken.GetSubject()
	if err != nil {
		subject = "" // 可选字段，不存在时返回空字符串
	}

	return Claims{
		Issuer:    issuer,
		ClientID:  clientID,
		Audience:  audience,
		Subject:   subject,
		IssuedAt:  issuedAt,
		ExpiresAt: expiresAt,
		JTI:       jti,
	}, nil
}

// SetStandardClaims 设置标准 Claims 到 PASETO Token
func (c *Claims) SetStandardClaims(token *paseto.Token) error {
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

// ==================== Getter 方法 ====================

func (c *Claims) GetIssuer() string           { return c.Issuer }
func (c *Claims) GetClientID() string         { return c.ClientID }
func (c *Claims) GetAudience() string         { return c.Audience }
func (c *Claims) GetSubject() string          { return c.Subject }
func (c *Claims) GetIssuedAt() time.Time      { return c.IssuedAt }
func (c *Claims) GetExpiresAt() time.Time     { return c.ExpiresAt }
func (c *Claims) GetJTI() string              { return c.JTI }
func (c *Claims) GetExpiresIn() time.Duration { return c.ExpiresIn }
func (c *Claims) IsExpired() bool             { return time.Now().After(c.ExpiresAt) }

// ==================== 辅助函数 ====================

func generateJTI() string {
	jtiBytes := make([]byte, 16)
	if _, err := rand.Read(jtiBytes); err != nil {
		// crypto/rand 失败说明系统熵源不可用，不应回退到可预测值
		panic(fmt.Sprintf("crypto/rand.Read failed: %v", err))
	}
	return hex.EncodeToString(jtiBytes)
}
