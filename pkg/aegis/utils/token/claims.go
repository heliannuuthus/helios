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
	issuer    string
	clientID  string
	audience  string
	subject   string
	expiresIn time.Duration
	issuedAt  time.Time
	expiresAt time.Time
	jti       string
}

// ==================== TokenTypeBuilder 接口 ====================

// TokenTypeBuilder Token 类型构建器接口
// 各 Token 类型实现此接口，用于 ClaimsBuilder.Build() 构建具体 Token
type TokenTypeBuilder interface {
	Build(claims Claims) Token
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
			jti: generateJTI(),
		},
	}
}

// Issuer 设置签发者
func (b *ClaimsBuilder) Issuer(issuer string) *ClaimsBuilder {
	b.claims.issuer = issuer
	return b
}

// ClientID 设置应用 ID
func (b *ClaimsBuilder) ClientID(clientID string) *ClaimsBuilder {
	b.claims.clientID = clientID
	return b
}

// Audience 设置目标受众
func (b *ClaimsBuilder) Audience(audience string) *ClaimsBuilder {
	b.claims.audience = audience
	return b
}

// Subject 设置主体
func (b *ClaimsBuilder) Subject(subject string) *ClaimsBuilder {
	b.claims.subject = subject
	return b
}

// ExpiresIn 设置有效期
func (b *ClaimsBuilder) ExpiresIn(expiresIn time.Duration) *ClaimsBuilder {
	b.claims.expiresIn = expiresIn
	return b
}

// Build 使用 TokenTypeBuilder 构建具体 Token
func (b *ClaimsBuilder) Build(typeBuilder TokenTypeBuilder) Token {
	return typeBuilder.Build(b.claims)
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

	var clientID string
	if err := pasetoToken.Get(ClaimCli, &clientID); err != nil {
		clientID = ""
	}

	subject, err := pasetoToken.GetSubject()
	if err != nil {
		subject = ""
	}

	return Claims{
		issuer:    issuer,
		clientID:  clientID,
		audience:  audience,
		subject:   subject,
		issuedAt:  issuedAt,
		expiresAt: expiresAt,
		jti:       jti,
	}, nil
}

// ==================== 辅助函数 ====================

func generateJTI() string {
	jtiBytes := make([]byte, 16)
	if _, err := rand.Read(jtiBytes); err != nil {
		panic(fmt.Sprintf("crypto/rand.Read failed: %v", err))
	}
	return hex.EncodeToString(jtiBytes)
}

// SetStandardClaims 设置标准 Claims 到 PASETO Token
func (c *Claims) SetStandardClaims(token *paseto.Token) error {
	now := time.Now()
	token.SetIssuer(c.issuer)
	token.SetAudience(c.audience)
	token.SetIssuedAt(now)
	token.SetExpiration(now.Add(c.expiresIn))
	token.SetNotBefore(now)
	token.SetJti(c.jti)

	if c.clientID != "" {
		if err := token.Set(ClaimCli, c.clientID); err != nil {
			return fmt.Errorf("set cli: %w", err)
		}
	}
	if c.subject != "" {
		token.SetSubject(c.subject)
	}
	return nil
}

// ==================== Token 接口实现 ====================

func (c *Claims) Issuer() string       { return c.issuer }
func (c *Claims) ClientID() string      { return c.clientID }
func (c *Claims) Audience() string      { return c.audience }
func (c *Claims) Subject() string       { return c.subject }
func (c *Claims) IssuedAt() time.Time   { return c.issuedAt }
func (c *Claims) ExpiresAt() time.Time  { return c.expiresAt }
func (c *Claims) ExpiresIn() time.Duration { return c.expiresIn }
func (c *Claims) IsExpired() bool       { return time.Now().After(c.expiresAt) }
